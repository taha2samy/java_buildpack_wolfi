#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import tarfile
import shutil
import platform
import subprocess
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

try:
    from jinja2 import Template
except ImportError:
    sys.exit(1)

G, Y, C, R, RESET, BOLD = "\033[0;32m", "\033[0;33m", "\033[0;36m", "\033[0;31m", "\033[0m", "\033[1m"
BP_ROOT = Path(__file__).parent.parent.resolve()

def log_step(action, detail=""):
    color = G if action in ["REUSE", "READY", "SUCCESS", "VERIFIED"] else Y
    print(f"     {BOLD}{'JRE-FIPS':<10}{RESET} : {color}{action:<10}{RESET} -> {detail}")

def verify_sha256(file_path, expected_sha):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest() == expected_sha

def get_jre_info(version):
    arch = "x64" if platform.machine() in ["x86_64", "AMD64"] else "aarch64"
    url = f"https://api.adoptium.net/v3/assets/latest/{version}/hotspot?os=linux&architecture={arch}&image_type=jre&vendor=eclipse"
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            asset = data[0]
            return {
                "url": asset['binary']['package']['link'],
                "sha256": asset['binary']['package']['checksum'],
                "version": asset['version']['openjdk_version'],
                "arch": arch
            }
    except Exception:
        return None

def download_file(url, target_path, expected_sha):
    if target_path.exists() and verify_sha256(target_path, expected_sha):
        return True
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(target_path, 'wb') as f:
            f.write(response.read())
    except Exception:
        return False
    return verify_sha256(target_path, expected_sha)

def generate_sbom(layers_dir, info, bc_config):
    sbom_tpl_path = BP_ROOT / "templates" / "sbom.jre.json.j2"
    if not sbom_tpl_path.exists():
        return
    template = Template(sbom_tpl_path.read_text())
    sbom_content = template.render(
        uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        version=info['version'],
        sha256=info['sha256'],
        arch=info['arch'],
        bc_fips_ver=bc_config['bouncycastle_fips_version'],
        bc_fips_sha=bc_config['bouncycastle_fips_sha'],
        bc_util_ver=bc_config['bouncycastle_util_fips_version'],
        bc_util_sha=bc_config['bouncycastle_util_fips_sha'],
        bc_tls_ver=bc_config['bouncycastle_tls_fips_version'],
        bc_tls_sha=bc_config['bouncycastle_tls_fips_sha']
    )
    (layers_dir /"jre.sbom.cdx.json").write_text(sbom_content)
    log_step("SBOM", "launch.sbom.jre.cdx.json generated")

def install_jre_fips(layers_dir, version, is_jdk_mode=False):
    layers_dir = Path(layers_dir).resolve()
    jre_layer, jre_toml = layers_dir / "jre", layers_dir / "jre.toml"
    config_path, tpl_path = BP_ROOT / "config" / "bouncycastle.json", BP_ROOT / "templates" / "java.security.j2"
    with open(config_path, 'r') as f:
        bc_config = json.load(f)
    info = get_jre_info(version)
    if not info:
        return False
    current_sha = ""
    if jre_toml.exists():
        import re
        match = re.search(r'sha256\s*=\s*"(\w+)"', jre_toml.read_text())
        if match:
            current_sha = match.group(1)
    if current_sha != info['sha256'] or not jre_layer.exists():
        log_step("UPDATE", f"Hardening JRE {info['version']}")
        tar_path = Path("/tmp/jre_bundle.tar.gz")
        if not download_file(info['url'], tar_path, info['sha256']):
            return False
        if jre_layer.exists():
            shutil.rmtree(jre_layer)
        jre_layer.mkdir(parents=True)
        with tarfile.open(tar_path) as tar:
            for m in tar.getmembers():
                if '/' in m.name:
                    m.name = m.name.split('/', 1)[1]
                    if m.name:
                        tar.extract(m, path=jre_layer)
        if tar_path.exists():
            os.remove(tar_path)
        bc_dest, sec_dir = jre_layer / "lib", jre_layer / "conf/security"
        bc_dest.mkdir(parents=True, exist_ok=True)
        sec_dir.mkdir(parents=True, exist_ok=True)
        for key in ["fips", "util_fips", "tls_fips"]:
            url, sha = bc_config[f"bouncycastle_{key}_url"], bc_config[f"bouncycastle_{key}_sha"]
            download_file(url, bc_dest / url.split('/')[-1], sha)
        template = Template(tpl_path.read_text())
        (sec_dir / "java.security").write_text(template.render(version=version))
        convert_keystore(jre_layer, jre_layer / "lib/security", bc_dest)
        generate_sbom(layers_dir, info, bc_config)
    else:
        log_step("REUSE", f"v{info['version']}")
        generate_sbom(layers_dir, info, bc_config)
    setup_env(jre_layer, jre_layer / "lib", jre_layer / "lib/security")
    jre_toml.write_text(f'[types]\nlaunch = {"false" if is_jdk_mode else "true"}\nbuild = false\ncache = true\n\n[metadata]\nversion = "{info["version"]}"\nsha256 = "{info["sha256"]}"')
    return True

def convert_keystore(jre_path, ks_dir, bc_dest):
    cacerts, backup, temp = ks_dir / "cacerts", ks_dir / "cacerts.old", ks_dir / "cacerts.bcfks"
    if not cacerts.exists() or backup.exists():
        return
    shutil.copy2(cacerts, backup)
    bc_fips = next(bc_dest.glob("bc-fips-*.jar"))
    bc_util = next(bc_dest.glob("bcutil-fips-*.jar"))
    cmd = [str(jre_path / "bin/keytool"), "-importkeystore", "-srckeystore", str(backup), "-srcstorepass", "changeit", "-srcstoretype", "PKCS12", "-destkeystore", str(temp), "-deststoretype", "BCFKS", "-deststorepass", "changeit", "-providerpath", f"{bc_fips}:{bc_util}", "-provider", "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider", "-noprompt"]
    env = os.environ.copy()
    env.pop("JAVA_TOOL_OPTIONS", None)
    if subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL).returncode == 0:
        shutil.move(str(temp), str(cacerts))

def setup_env(jre_layer, bc_dest, ks_dir):
    env_launch = jre_layer / "env.launch"
    env_launch.mkdir(exist_ok=True)
    
    with open(env_launch / "JAVA_HOME", "wb") as f:
        f.write(str(jre_layer).encode('utf-8'))
    with open(env_launch / "PATH.prepend", "wb") as f:
        f.write(str(jre_layer / "bin").encode('utf-8'))
    with open(env_launch / "PATH.delim", "wb") as f:
        f.write(b":")
    with open(env_launch / "MALLOC_ARENA_MAX", "wb") as f:
        f.write(b"2")
        
    bc_jars = []
    for prefix in ["bc-fips", "bcutil-fips", "bctls-fips"]:
        match = list(bc_dest.glob(f"{prefix}*.jar"))
        if match:
            bc_jars.append(str(match[0].resolve()))
    boot = ":".join(bc_jars)
    
    headroom = int(os.getenv("BPL_JVM_HEAD_ROOM", "25"))
    ram_percentage = float(100 - headroom)
    
    fips_opts = (f"-Dorg.bouncycastle.fips.approved_only=true "
                 f"-Dorg.bouncycastle.crypto.fips.seeder=DEVURANDOM "
                 f"-Dkeystore.type=BCFKS "
                 f"-Djavax.net.ssl.trustStore={ks_dir.resolve()}/cacerts "
                 f"-Djavax.net.ssl.trustStoreType=BCFKS "
                 f"-Djavax.net.ssl.trustStorePassword=changeit "
                 f"-Xbootclasspath/a:{boot} "
                 f"-XX:+ExitOnOutOfMemoryError "
                 f"-XX:+UseContainerSupport "
                 f"-XX:MaxRAMPercentage={ram_percentage} "
                 f"-Dfile.encoding=UTF-8 "
                 f"-Dsun.net.inetaddr.ttl=60 "
                 f"-XX:+UnlockExperimentalVMOptions")

    if os.getenv("BPL_JAVA_NMT_ENABLED", "true").lower() == "true":
        nmt_level = os.getenv("BPL_JAVA_NMT_LEVEL", "summary")
        fips_opts += f" -XX:NativeMemoryTracking={nmt_level} -XX:+UnlockDiagnosticVMOptions -XX:+PrintNMTStatistics"

    if os.getenv("BPL_JMX_ENABLED", "false").lower() == "true":
        jmx_port = os.getenv("BPL_JMX_PORT", "5000")
        fips_opts += (f" -Djava.rmi.server.hostname=127.0.0.1 "
                      f"-Dcom.sun.management.jmxremote.authenticate=false "
                      f"-Dcom.sun.management.jmxremote.ssl=false "
                      f"-Dcom.sun.management.jmxremote.rmi.port={jmx_port}")

    if os.getenv("BPL_DEBUG_ENABLED", "false").lower() == "true":
        debug_port = os.getenv("BPL_DEBUG_PORT", "8000")
        suspend = "y" if os.getenv("BPL_DEBUG_SUSPEND", "false").lower() == "true" else "n"
        fips_opts += f" -agentlib:jdwp=transport=dt_socket,server=y,address=*:{debug_port},suspend={suspend}"

    if os.getenv("BPL_JFR_ENABLED", "false").lower() == "true":
        jfr_args = os.getenv("BPL_JFR_ARGS", "dumponexit=true,filename=/tmp/recording.jfr")
        fips_opts += f" -XX:StartFlightRecording={jfr_args}"

    heap_dump_path = os.getenv("BPL_HEAP_DUMP_PATH")
    if heap_dump_path:
        fips_opts += f" -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath={heap_dump_path}"

    with open(env_launch / "JAVA_TOOL_OPTIONS.append", "ab") as f:
        f.write(f" {fips_opts}".encode('utf-8'))
    with open(env_launch / "JAVA_TOOL_OPTIONS.delim", "wb") as f:
        f.write(b" ")
if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(1)
    install_jre_fips(sys.argv[1], sys.argv[2], (sys.argv[3].lower() == "jdk" if len(sys.argv) > 3 else False))
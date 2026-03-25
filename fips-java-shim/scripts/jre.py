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
from pathlib import Path

try:
    from jinja2 import Template
except ImportError:
    sys.exit(1)

G, Y, C, R, RESET, BOLD = "\033[0;32m", "\033[0;33m", "\033[0;36m", "\033[0;31m", "\033[0m", "\033[1m"
BP_ROOT = Path(__file__).parent.parent.resolve()

def log_header(title):
    print(f"\n{BOLD}{C}===> {title}{RESET}")

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
                "version": asset['version']['openjdk_version']
            }
    except Exception:
        return None

def download_file(url, target_path, expected_sha):
    if target_path.exists() and verify_sha256(target_path, expected_sha):
        return True
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response, open(target_path, 'wb') as f:
            f.write(response.read())
    except Exception:
        return False
    return verify_sha256(target_path, expected_sha)

def install_jre_fips(layers_dir, version, is_jdk_mode=False):
    layers_dir = Path(layers_dir).resolve()
    jre_layer = layers_dir / "jre"
    jre_toml = layers_dir / "jre.toml"
    config_path = BP_ROOT / "config" / "bouncycastle.json"
    tpl_path = BP_ROOT / "templates" / "java.security.j2"

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

        if version == "8":
            bc_dest = jre_layer / "lib/ext"
            sec_dir = jre_layer / "lib/security"
        else:
            bc_dest = jre_layer / "lib"
            sec_dir = jre_layer / "conf/security"

        bc_dest.mkdir(parents=True, exist_ok=True)
        sec_dir.mkdir(parents=True, exist_ok=True)

        for key in ["fips", "util_fips", "tls_fips"]:
            url = bc_config[f"bouncycastle_{key}_url"]
            sha = bc_config[f"bouncycastle_{key}_sha"]
            download_file(url, bc_dest / url.split('/')[-1], sha)

        template = Template(tpl_path.read_text())
        (sec_dir / "java.security").write_text(template.render(version=version))

        convert_keystore(jre_layer, jre_layer / "lib/security", bc_dest)

    else:
        log_step("REUSE", f"v{info['version']}")

    setup_env(
        jre_layer,
        bc_dest,
        jre_layer / "lib/security",
        sec_dir / "java.security" if version != "8" else jre_layer / "lib/security/java.security"
    )

    launch_val = "false" if is_jdk_mode else "true"

    jre_toml.write_text(
        f'[types]\nlaunch = {launch_val}\nbuild = false\ncache = true\n\n'
        f'[metadata]\nversion = "{info["version"]}"\nsha256 = "{info["sha256"]}"'
    )

    return True

def convert_keystore(jre_path, ks_dir, bc_dest):
    cacerts = ks_dir / "cacerts"
    backup = ks_dir / "cacerts.old"
    temp = ks_dir / "cacerts.bcfks"

    if not cacerts.exists() or backup.exists():
        return

    shutil.copy2(cacerts, backup)

    bc_fips = next(bc_dest.glob("bc-fips-*.jar"))
    bc_util = next(bc_dest.glob("bcutil-fips-*.jar"))

    clean_env = os.environ.copy()
    clean_env.pop("JAVA_TOOL_OPTIONS", None)

    cmd = [
        str(jre_path / "bin/keytool"),
        "-importkeystore",
        "-srckeystore", str(backup),
        "-srcstorepass", "changeit",
        "-srcstoretype", "PKCS12",
        "-destkeystore", str(temp),
        "-deststoretype", "BCFKS",
        "-deststorepass", "changeit",
        "-providerpath", f"{bc_fips}:{bc_util}",
        "-provider", "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider",
        "-noprompt"
    ]

    if subprocess.run(cmd, env=clean_env, stdout=subprocess.DEVNULL).returncode == 0:
        shutil.move(str(temp), str(cacerts))

def setup_env(jre_layer, bc_dest, ks_dir, sec_file):
    env_launch = jre_layer / "env.launch"
    env_launch.mkdir(exist_ok=True)

    (env_launch / "JAVA_HOME").write_text(str(jre_layer))
    (env_launch / "PATH.prepend").write_text(str(jre_layer / "bin"))
    (env_launch / "PATH.delim").write_text(":")

    bc_jars = []
    for prefix in ["bc-fips", "bcutil-fips", "bctls-fips"]:
        match = list(bc_dest.glob(f"{prefix}*.jar"))
        if match:
            bc_jars.append(str(match[0].resolve()))

    boot = ":".join(bc_jars)


    fips_opts = (
        f"-Dorg.bouncycastle.fips.approved_only=true "
        f"-Dorg.bouncycastle.fips.native_secure_random=true "
        f"-Dorg.bouncycastle.crypto.fips.seeder=NATIVE "
        f"-Djava.security.egd=file:/dev/urandom "
        f"-Djava.security.properties={sec_file.resolve()} "
        f"-Dkeystore.type=BCFKS "
        f"-Djavax.net.ssl.trustStore={ks_dir.resolve()}/cacerts "
        f"-Djavax.net.ssl.trustStoreType=BCFKS "
        f"-Djavax.net.ssl.trustStorePassword=changeit "
        f"-Xbootclasspath/a:{boot} "
        f"-XX:+ExitOnOutOfMemoryError -XX:MaxRAMPercentage=75.0"
    )

    (env_launch / "JAVA_TOOL_OPTIONS.append").write_text(fips_opts)
    (env_launch / "JAVA_TOOL_OPTIONS.delim").write_text(" ")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(1)

    target_layers, java_ver = sys.argv[1], sys.argv[2]
    jtype = sys.argv[3].lower() if len(sys.argv) > 3 else "jre"

    install_jre_fips(target_layers, java_ver, (jtype == "jdk"))
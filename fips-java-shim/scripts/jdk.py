#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import tarfile
import shutil
import platform
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
    print(f"     {BOLD}{'JDK':<10}{RESET} : {G if action in ['REUSE', 'READY', 'SUCCESS'] else Y}{action:<10}{RESET} -> {detail}")

def verify_sha256(file_path, expected_sha):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest() == expected_sha

def get_latest_jdk_info(version):
    arch = "x64" if platform.machine() in ["x86_64", "AMD64"] else "aarch64"
    url = f"https://api.adoptium.net/v3/assets/latest/{version}/hotspot?os=linux&architecture={arch}&image_type=jdk&vendor=eclipse"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            asset = data[0]
            return {"url": asset['binary']['package']['link'], "sha256": asset['binary']['package']['checksum'], "version": asset['version']['openjdk_version'], "arch": arch}
    except Exception: return None

def generate_sbom(layers_dir, info):
    sbom_tpl_path = BP_ROOT / "templates" / "sbom.jdk.json.j2"
    if not sbom_tpl_path.exists(): return
    template = Template(sbom_tpl_path.read_text())
    sbom_content = template.render(
        uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        version=info['version'],
        sha256=info['sha256'],
        arch=info['arch'],
        url=info['url']
    )
    (layers_dir / "launch.sbom.cdx.json").write_text(sbom_content)
    log_step("SBOM", "jdk.sbom.cdx.json generated")

def install_jdk(layers_dir, version, launch=False):
    layers_dir = Path(layers_dir).resolve()
    jdk_layer, jdk_toml = layers_dir / "jdk", layers_dir / "jdk.toml"
    info = get_latest_jdk_info(version)
    if not info: return False
    current_sha = ""
    if jdk_toml.exists():
        import re
        match = re.search(r'sha256\s*=\s*"(\w+)"', jdk_toml.read_text())
        if match: current_sha = match.group(1)
    
    if current_sha == info['sha256'] and jdk_layer.exists():
        log_step("REUSE", f"v{info['version']}")
        generate_sbom(layers_dir, info)
    else:
        log_step("DOWNLOAD", info['url'])
        tar_path = Path("/tmp/jdk.tar.gz")
        urllib.request.urlretrieve(info['url'], tar_path)
        if not verify_sha256(tar_path, info['sha256']): return False
        if jdk_layer.exists(): shutil.rmtree(jdk_layer)
        jdk_layer.mkdir(parents=True)
        with tarfile.open(tar_path) as tar:
            for m in tar.getmembers():
                if '/' in m.name:
                    m.name = m.name.split('/', 1)[1]
                    if m.name: tar.extract(m, path=jdk_layer)
        if tar_path.exists(): os.remove(tar_path)
        generate_sbom(layers_dir, info)
    
    jdk_toml.write_text(f'[types]\nbuild = true\ncache = true\nlaunch = {str(launch).lower()}\n\n[metadata]\nversion = "{info["version"]}"\nsha256 = "{info["sha256"]}"')
    
    headroom = int(os.getenv("BPL_JVM_HEAD_ROOM", "25"))
    ram_percentage = float(100 - headroom)
    
    memory_opts = (
        f"-XX:+UseContainerSupport "
        f"-XX:MaxRAMPercentage={ram_percentage} "
        f"-XX:InitialRAMPercentage={ram_percentage}"
    )

    for phase in ["build", "launch"]:
        if phase == "launch" and not launch: continue
        env_dir = jdk_layer / f"env.{phase}"
        env_dir.mkdir(exist_ok=True)
        with open(env_dir / "JAVA_HOME", "wb") as f: f.write(str(jdk_layer).encode('utf-8'))
        with open(env_dir / "PATH.prepend", "wb") as f: f.write(str(jdk_layer / "bin").encode('utf-8'))
        with open(env_dir / "PATH.delim", "wb") as f: f.write(b":")
        # Use 'ab' to append and match JRE logic
        with open(env_dir / "JAVA_TOOL_OPTIONS.append", "ab") as f:
            f.write(f" -XX:+ExitOnOutOfMemoryError {memory_opts} -Dfile.encoding=UTF-8".encode('utf-8'))
        with open(env_dir / "JAVA_TOOL_OPTIONS.delim", "wb") as f:
            f.write(b" ")
            
    log_step("READY", f"JDK {info['version']} installed.")
    return True
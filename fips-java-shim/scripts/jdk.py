#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import tarfile
import shutil
import platform
import urllib.request
from pathlib import Path

G, Y, C, R, RESET, BOLD = "\033[0;32m", "\033[0;33m", "\033[0;36m", "\033[0;31m", "\033[0m", "\033[1m"

def log_step(action, detail=""):
    print(f"     {BOLD}{'JDK':<10}{RESET} : {G if action in ['REUSE', 'READY'] else Y}{action:<10}{RESET} -> {detail}")

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
            return {
                "url": asset['binary']['package']['link'],
                "sha256": asset['binary']['package']['checksum'],
                "version": asset['version']['openjdk_version']
            }
    except Exception as e:
        print(f"{R}API Error: {e}{RESET}")
        return None

def install_jdk(layers_dir, version, launch=False):
    layers_dir = Path(layers_dir)
    jdk_layer = layers_dir / "jdk"
    jdk_toml = layers_dir / "jdk.toml"
    
    info = get_latest_jdk_info(version)
    if not info: return False

    current_sha = ""
    if jdk_toml.exists():
        import re
        match = re.search(r'sha256\s*=\s*"(\w+)"', jdk_toml.read_text())
        if match: current_sha = match.group(1)

    if current_sha == info['sha256'] and jdk_layer.exists():
        log_step("REUSE", f"v{info['version']}")
    else:
        log_step("DOWNLOAD", info['url'])
        tar_path = Path("/tmp/jdk.tar.gz")
        req_dl = urllib.request.Request(info['url'], headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req_dl) as response, open(tar_path, 'wb') as f:
            f.write(response.read())
        
        if not verify_sha256(tar_path, info['sha256']):
            print(f"{R}Checksum fail!{RESET}")
            return False

        if jdk_layer.exists(): shutil.rmtree(jdk_layer)
        jdk_layer.mkdir(parents=True)
        
        with tarfile.open(tar_path) as tar:
            for m in tar.getmembers():
                if '/' in m.name:
                    m.name = m.name.split('/', 1)[1]
                    if m.name: tar.extract(m, path=jdk_layer)
        
        if tar_path.exists(): os.remove(tar_path)

    jdk_toml.write_text(f"""[types]
build = true
cache = true
launch = {str(launch).lower()}

[metadata]
version = "{info['version']}"
sha256 = "{info['sha256']}"
    """)

    for phase in ["build", "launch"]:
        if phase == "launch" and not launch: continue
        env_dir = jdk_layer / f"env.{phase}"
        env_dir.mkdir(exist_ok=True)
        (env_dir / "JAVA_HOME").write_text(str(jdk_layer))
        (env_dir / "PATH.prepend").write_text(str(jdk_layer / "bin"))
        (env_dir / "PATH.delim").write_text(":")
        (env_dir / "JAVA_TOOL_OPTIONS.append").write_text("-XX:+ExitOnOutOfMemoryError -Dfile.encoding=UTF-8")
        (env_dir / "JAVA_TOOL_OPTIONS.delim").write_text(" ")

    log_step("READY", f"JDK {info['version']} installed.")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: jdk.py <layers_dir> <version> <launch_true_false>")
        sys.exit(1)
    
    target_layers = sys.argv[1]
    java_ver = sys.argv[2] if len(sys.argv) > 2 else "21"
    is_launch = sys.argv[3].lower() == "true" if len(sys.argv) > 3 else False
    
    print(f"\n{BOLD}{C}===> Executing JDK Module (Launch={is_launch}){RESET}")
    if install_jdk(target_layers, java_ver, is_launch):
        print(f"{G}{BOLD}DONE{RESET}\n")
    else:
        sys.exit(1)
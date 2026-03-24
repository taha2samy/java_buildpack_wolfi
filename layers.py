#!/usr/bin/env python3
import sys
import subprocess
import json
import csv

def main():
    if len(sys.argv) < 3:
        print("Usage: ./analyze.py <image_name> <csv_path>")
        sys.exit(1)

    image_name, csv_path = sys.argv[1], sys.argv[2]

    try:
        subprocess.run(f"dive {image_name} --json image_report.json", shell=True, check=True, capture_output=True)

        with open("image_report.json", 'r') as f:
            data = json.load(f)

        layers = []
        for layer in data.get("layer", []):
            size_mb = layer.get("sizeBytes", 0) / (1024 * 1024)
            cmd = layer.get("command", "").replace("\n", " ")
            layers.append({"size": size_mb, "cmd": cmd, "sha": layer.get("digestId")})

        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["LAYER_TYPE", "SIZE_MB", "SHA256_HASH", "COMMAND"])

            for l in layers:
                if "taha/fips-java" in l['cmd']:
                    layer_type = "JRE/FIPS Layer"
                elif "Application Slice" in l['cmd']:
                    layer_type = "App Code Layer"
                elif "paketo-buildpacks" in l['cmd']:
                    layer_type = "Buildpack Helper"
                else:
                    layer_type = "OS/Base Layer"

                writer.writerow([layer_type, f"{l['size']:.6f} MB", l['sha'], l['cmd']])

        print(f"Success! Detailed report: {csv_path}")

        print("\n--- Top 5 Largest Layers ---")
        top_layers = sorted(layers, key=lambda x: x['size'], reverse=True)[:5]
        for i, l in enumerate(top_layers, 1):
            print(f"{i}. {l['size']:.6f} MB | {l['sha'][:12]}... | {l['cmd'][:40]}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
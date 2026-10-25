#!/usr/bin/env python3
"""Bind release binaries to the exact tag and already verified image proof."""

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys


def binary_record(directory, architecture):
    machine = {"amd64": 62, "arm64": 183}[architecture]
    name = "tx-node-linux-" + architecture
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("release binary missing")
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != machine:
        raise ValueError("release binary architecture differs")
    return {"file": name, "platform": "linux/" + architecture, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def record(root, directory, architecture, tag, commit):
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if actual != commit:
        raise ValueError("binary build checkout differs")
    proof = binary_record(directory, architecture) | {"commit": commit, "tag": tag,
        "tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()}
    (directory / (proof["file"] + ".build.json")).write_text(json.dumps(proof, indent=2) + "\n")
    return proof


def prepare(root, directory, image_directory, tag, commit, run_id):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-(?:rc|beta|preview)\.[1-9][0-9]*)?", tag):
        raise ValueError("unsupported release tag")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("exact release source required")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if actual != commit:
        raise ValueError("release checkout differs from tag source")
    image = json.loads((image_directory / "verification.json").read_text())
    if (image.get("schema") != "txnode-published-image/v1" or image.get("accepted") is not True or image.get("commit") != commit
            or image.get("version") != tag or image.get("source") != "https://github.com/ANRCM0/TXnode"
            or re.fullmatch(r"ghcr.io/anrcm0/txnode@sha256:[a-f0-9]{64}", image.get("image", "")) is None):
        raise ValueError("matching published image proof required")
    platforms = image.get("images", [])
    if sorted(item.get("platform", "") for item in platforms) != ["linux/amd64", "linux/arm64"]:
        raise ValueError("both published architectures required")
    if any(item.get("metadata_verified") is not True or item.get("offline_capabilities_verified") is not True
           or re.fullmatch(r"sha256:[a-f0-9]{64}", item.get("digest", "")) is None for item in platforms):
        raise ValueError("published architecture verification missing")
    binaries = []
    checksums = []
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
    for architecture in ("amd64", "arm64"):
        binary = binary_record(directory, architecture)
        proof = json.loads((directory / (binary["file"] + ".build.json")).read_text())
        if proof != binary | {"commit": commit, "tag": tag, "tree": tree}:
            raise ValueError("binary differs from its exact-source build record")
        binaries.append(proof)
        checksums.append(binary["sha256"] + "  " + binary["file"])
    baseline = json.loads((root / "compatibility/core.v1.json").read_text())
    if baseline.get("repository") != "ANRCM0/TXBoard" or re.fullmatch(r"[a-f0-9]{40}", baseline.get("revision", "")) is None:
        raise ValueError("exact supported Core identity required")
    manifest = {"schema": "txnode-release-manifest/v1", "tag": tag, "commit": commit, "tree": tree,
                "workflow_run_id": run_id, "core": baseline, "binaries": binaries, "published_image": image,
                "scope": "binary checksums and exact-source published image verification; performance and physical rollout have separate acceptance records"}
    (directory / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    (directory / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("release asset assembly runs in Actions")
    root = Path(__file__).resolve().parents[1]
    if sys.argv[1:] == ["--record"]:
        proof = record(root, root, os.environ["GOARCH"], os.environ["GITHUB_REF_NAME"], os.environ["GITHUB_SHA"])
        print(json.dumps(proof))
        raise SystemExit(0)
    if sys.argv[1:]:
        raise SystemExit("unknown release assembly arguments")
    result = prepare(root, root / "dist", root / "release-image-proof", os.environ["GITHUB_REF_NAME"],
                     os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"])
    print(json.dumps({"tag": result["tag"], "commit": result["commit"], "binaries": result["binaries"]}))

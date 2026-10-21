#!/usr/bin/env python3
"""Verify the actual published index and run both images offline in Actions."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess


def command(*arguments):
    return subprocess.check_output(arguments, text=True)


def verify(args):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("published container acceptance runs only in GitHub Actions")
    repository, separator, digest = args.image.partition("@")
    if not separator or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("published image must use an immutable index digest")
    if not re.fullmatch(r"[a-f0-9]{40}", args.commit):
        raise ValueError("expected commit must be an exact SHA")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    raw = command("docker", "buildx", "imagetools", "inspect", args.image, "--raw")
    (output / "index.json").write_text(raw)
    index = json.loads(raw)
    images = []
    for descriptor in index["manifests"]:
        platform = descriptor.get("platform", {})
        if platform.get("os") == "unknown" and platform.get("architecture") == "unknown":
            continue  # BuildKit attestations are separate from runnable images.
        if platform.get("os") != "linux" or platform.get("architecture") not in ("amd64", "arm64"):
            raise ValueError("unexpected runnable platform in published index")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", descriptor.get("digest", "")):
            raise ValueError("invalid child image digest")
        images.append((platform["architecture"], descriptor["digest"]))
    if sorted(architecture for architecture, _ in images) != ["amd64", "arm64"]:
        raise ValueError("published index must contain exactly amd64 and arm64 images")
    results = []
    for architecture, child_digest in images:
        image = repository + "@" + child_digest
        command("docker", "pull", "--platform", "linux/" + architecture, image)
        raw = command("docker", "image", "inspect", image)
        (output / (architecture + "-image.json")).write_text(raw)
        metadata, = json.loads(raw)
        labels = metadata["Config"]["Labels"]
        if (metadata["Os"] != "linux" or metadata["Architecture"] != architecture
                or labels["org.opencontainers.image.source"] != args.source
                or labels["org.opencontainers.image.revision"] != args.commit
                or labels["org.opencontainers.image.version"] != args.version
                or metadata["Config"]["Cmd"] != ["-c", "/etc/txnode/config.yml"]):
            raise ValueError("published image platform, metadata or command mismatch")
        raw = command("docker", "run", "--rm", "--network", "none", "--platform",
                      "linux/" + architecture, image, "--capabilities")
        (output / (architecture + "-capabilities.json")).write_text(raw)
        proof = json.loads(raw)
        required = {"node_authorization_snapshot_v1", "node_runtime_checkpoint_v1",
                    "node_provider_credential_delivery_v1", "node_native_subscription_usage_v1"}
        if (proof["protocol_version"] != 1 or proof["runtime"] != "tx-node"
                or proof["commit"] != args.commit or proof["version"] != args.version
                or not required <= set(proof["capabilities"])):
            raise ValueError("published image offline runtime capability mismatch")
        results.append({"platform": "linux/" + architecture, "digest": child_digest,
                        "metadata_verified": True, "offline_capabilities_verified": True})
    report = {"schema": "txnode-published-image/v1", "image": args.image,
              "commit": args.commit, "source": args.source, "version": args.version,
              "images": results, "accepted": True,
              "scope": "registry digest, image metadata and offline capability execution; arm64 uses QEMU"}
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    verify(parser.parse_args())

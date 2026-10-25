import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("release_assets", Path(__file__).with_name("prepare-release-assets.py"))
assets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assets)


class ReleaseAssetsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "dist"
        self.image_directory = self.root / "image"
        self.directory.mkdir()
        self.image_directory.mkdir()
        (self.root / "compatibility").mkdir()
        (self.root / "compatibility/core.v1.json").write_text(json.dumps({"repository": "ANRCM0/TXBoard", "revision": "a" * 40}))
        for arguments in (("init", "--quiet"), ("add", "compatibility"),
                          ("-c", "user.name=Release fixture", "-c", "user.email=release@example.test", "commit", "--quiet", "-m", "fixture")):
            subprocess.run(["git", *arguments], cwd=self.root, check=True, capture_output=True)
        self.commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()
        self.tag = "v2.3.0-rc.1"
        for architecture, machine in (("amd64", 62), ("arm64", 183)):
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", data, 18, machine)
            (self.directory / ("tx-node-linux-" + architecture)).write_bytes(data)
            assets.record(self.root, self.directory, architecture, self.tag, self.commit)
        self.image = {"schema": "txnode-published-image/v1", "accepted": True, "commit": self.commit, "version": self.tag,
            "source": "https://github.com/ANRCM0/TXnode", "image": "ghcr.io/anrcm0/txnode@sha256:" + "b" * 64,
            "images": [{"platform": "linux/" + arch, "digest": "sha256:" + digit * 64,
                        "metadata_verified": True, "offline_capabilities_verified": True}
                       for arch, digit in (("amd64", "c"), ("arm64", "d"))]}
        self.write_image(self.image)

    def write_image(self, value):
        (self.image_directory / "verification.json").write_text(json.dumps(value))

    def prepare(self):
        return assets.prepare(self.root, self.directory, self.image_directory, self.tag, self.commit, "123")

    def test_manifest_binds_both_original_builds_and_published_architectures(self):
        manifest = self.prepare()
        self.assertEqual(manifest["commit"], self.commit)
        self.assertEqual([item["platform"] for item in manifest["binaries"]], ["linux/amd64", "linux/arm64"])
        self.assertEqual(manifest["published_image"], self.image)
        self.assertEqual(len((self.directory / "SHA256SUMS").read_text().splitlines()), 2)

    def test_wrong_source_version_platform_and_incomplete_image_proof_are_rejected(self):
        variants = []
        for key, value in (("commit", "0" * 40), ("version", "v2.3.0"), ("accepted", False)):
            bad = copy.deepcopy(self.image)
            bad[key] = value
            variants.append(bad)
        bad = copy.deepcopy(self.image)
        bad["images"][1]["platform"] = "linux/amd64"
        variants.append(bad)
        bad = copy.deepcopy(self.image)
        bad["images"][0]["offline_capabilities_verified"] = False
        variants.append(bad)
        for value in variants:
            with self.subTest(value=value):
                self.write_image(value)
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_post_build_binary_changes_and_mixed_source_build_records_are_rejected(self):
        binary = self.directory / "tx-node-linux-amd64"
        original = binary.read_bytes()
        binary.write_bytes(original + b"changed")
        with self.assertRaisesRegex(ValueError, "build record"):
            self.prepare()
        binary.write_bytes(original)
        path = self.directory / "tx-node-linux-arm64.build.json"
        proof = json.loads(path.read_text())
        proof["commit"] = "0" * 40
        path.write_text(json.dumps(proof))
        with self.assertRaisesRegex(ValueError, "build record"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()

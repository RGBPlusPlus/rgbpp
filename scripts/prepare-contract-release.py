"""Package the exact production binaries that passed the checksum and VM tests."""

import argparse
import hashlib
import json
from pathlib import Path
import re

CONTRACTS = ("btc-time-lock", "rgbpp-lock")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--build-image", required=True)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("expected the full source commit SHA")
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", args.build_image):
        parser.error("expected a digest-pinned build image")

    checksums = {}
    for line in Path("checksums.txt").read_text(encoding="utf-8").splitlines():
        digest, build_path = line.split()
        checksums[build_path] = digest

    contracts = []
    binaries = {}
    for name in CONTRACTS:
        data = (Path("build/non-mock") / name).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if not data or checksums.get(f"build/release/{name}") != digest:
            raise ValueError(f"{name}: did not match the committed production checksum")
        binaries[name] = data
        contracts.append(
            {
                "name": name,
                "size_bytes": len(data),
                "sha256": digest,
                "ckb_data_hash": "0x"
                + hashlib.blake2b(data, digest_size=32, person=b"ckb-default-hash").hexdigest(),
            }
        )

    args.output_dir.mkdir()
    for name, data in binaries.items():
        (args.output_dir / name).write_bytes(data)
    (args.output_dir / "SHA256SUMS").write_text(
        "".join(f"{item['sha256']}  {item['name']}\n" for item in contracts), encoding="utf-8"
    )
    (args.output_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_commit": args.source_commit,
                "build_image": args.build_image,
                "contracts": contracts,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

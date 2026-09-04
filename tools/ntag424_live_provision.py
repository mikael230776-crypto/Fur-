#!/usr/bin/env python3
"""Locked release candidate for controlled FUR NTAG 424 DNA provisioning."""

import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntag424_execution_manifest import build_manifest
from ntag424_locked_transport import safety_check as transport_safety_check
from ntag424_provision import PROVISIONING_STEPS

LIVE_EXECUTION_ENABLED = False
AUTHORISATION_PHRASE = "PROVISION FUR TAG PERMANENTLY"


def release_candidate_check(tag_id: str, expected_uid: str) -> dict:
    manifest = build_manifest(tag_id, expected_uid)
    transport_safety_check()
    if LIVE_EXECUTION_ENABLED:
        raise RuntimeError("Safety build must not enable live execution")
    if PROVISIONING_STEPS[-2].action != "Replace administration key 0 last":
        raise RuntimeError("Administration key recovery boundary changed")
    if manifest["recovery_boundary"] != "key-0-last":
        raise RuntimeError("Manifest recovery boundary changed")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--safety-check", action="store_true")
    parser.add_argument("--tag-id", default="FUR-000001")
    parser.add_argument("--expected-uid", required=True)
    args = parser.parse_args()
    try:
        manifest = release_candidate_check(args.tag_id, args.expected_uid)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"LIVE PROVISIONER CHECK FAILED — {error}")
        return 1
    print("FUR NTAG 424 DNA — LIVE PROVISIONER RELEASE CANDIDATE")
    print("Reader access: DISABLED")
    print("Persistent tag writes: BLOCKED")
    print(f"Manifest SHA-256: {manifest['manifest_sha256']}")
    print("Identity, keys, payload, SDM profile and recovery order: VERIFIED")
    print("LIVE PROVISIONER SAFETY BUILD PASSED — EXECUTION IS NOT ENABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

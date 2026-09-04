#!/usr/bin/env python3
"""Build a sealed, reader-free manifest for FUR NTAG 424 DNA provisioning."""

import argparse
import hashlib
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntag424_dry_run import build_change_file_settings_data, build_plan
from ntag424_provision import EXPECTED_SETTINGS, normalise_uid, validate_production_keys

ORDER = (
    "preflight",
    "keys-1-4",
    "ndef-write-readback",
    "sdm-settings-readback",
    "key-0-last",
    "production-reauth-sun",
)


def build_manifest(tag_id: str, expected_uid: str) -> dict:
    uid = normalise_uid(expected_uid)
    validate_production_keys()
    plan = build_plan(tag_id)
    settings = build_change_file_settings_data(plan)
    if settings != EXPECTED_SETTINGS:
        raise ValueError("Locked FUR SDM profile mismatch")
    if len(plan.ndef_file) != 107:
        raise ValueError("Locked FUR NDEF length mismatch")

    manifest = {
        "schema": "fur-ntag424-provisioning-manifest-v1",
        "tag_id": plan.tag_id,
        "expected_uid": uid,
        "ndef_length": len(plan.ndef_file),
        "ndef_sha256": hashlib.sha256(plan.ndef_file).hexdigest(),
        "change_file_settings": settings.hex().upper(),
        "operation_order": list(ORDER),
        "recovery_boundary": "key-0-last",
        "reader_access": "disabled",
        "physical_writes": "disabled",
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-id", default="FUR-000001")
    parser.add_argument("--expected-uid", required=True)
    args = parser.parse_args()
    try:
        manifest = build_manifest(args.tag_id, args.expected_uid)
    except (ValueError, OSError) as error:
        print(f"EXECUTION MANIFEST FAILED — {error}")
        return 1

    print("FUR NTAG 424 DNA — LOCKED EXECUTION MANIFEST")
    print("Reader access: DISABLED")
    print("Physical tag writes: DISABLED")
    print(f"Tag ID: {manifest['tag_id']}")
    print(f"Expected UID: {manifest['expected_uid']}")
    print(f"NDEF payload: {manifest['ndef_length']} bytes — SEALED")
    print("FUR SDM profile: SEALED")
    print("Key order and recovery boundary: SEALED")
    print(f"Manifest SHA-256: {manifest['manifest_sha256']}")
    print("EXECUTION MANIFEST READY — NO READER OR TAG WAS ACCESSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

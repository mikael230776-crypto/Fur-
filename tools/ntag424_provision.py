#!/usr/bin/env python3
"""Offline safety gate for FUR NTAG 424 DNA provisioning.

This file deliberately has no smartcard import and no APDU transmit function.
It validates the identity, production keys, FUR SDM profile, and recovery-safe
operation order before a separate reviewed executor may be enabled.
"""

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntag424_dry_run import build_change_file_settings_data, build_plan

EXPECTED_SETTINGS = bytes.fromhex("4000E0C1F0E13C00004F00005B00005B0000")
KEYCHAIN_SERVICES = (
    "FUR NTAG 424 Admin Key",
    "FUR SUN SDM Key",
    "FUR NTAG 424 Key 2",
    "FUR NTAG 424 Key 3",
    "FUR NTAG 424 Key 4",
)


@dataclass(frozen=True)
class ProvisioningStep:
    number: int
    action: str
    recovery_checkpoint: str


PROVISIONING_STEPS: Tuple[ProvisioningStep, ...] = (
    ProvisioningStep(1, "Read-only identity and file-settings preflight", "No change"),
    ProvisioningStep(2, "Authenticate the current factory administration key 0", "No change"),
    ProvisioningStep(3, "Replace and verify application keys 1, 2, 3 and 4", "Factory key 0 retained"),
    ProvisioningStep(4, "Write the 107-byte FUR NDEF payload and read it back", "Factory key 0 retained"),
    ProvisioningStep(5, "Apply and read back the FUR SDM file settings", "Factory key 0 retained"),
    ProvisioningStep(6, "Replace administration key 0 last", "Production keys installed"),
    ProvisioningStep(7, "Re-authenticate with production key 0 and verify SUN", "Provisioning complete"),
)


def normalise_uid(value: str) -> str:
    uid = value.strip().upper()
    if re.fullmatch(r"[0-9A-F]{14}", uid) is None:
        raise ValueError("Expected UID must contain exactly 14 hexadecimal characters")
    return uid


def keychain_value(service: str) -> str:
    account = subprocess.check_output(["id", "-un"], text=True).strip()
    return subprocess.check_output(
        [
            "security",
            "find-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
        ],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()


def validate_production_keys() -> None:
    keys = [keychain_value(service) for service in KEYCHAIN_SERVICES]
    if not all(re.fullmatch(r"[0-9A-Fa-f]{32}", key) for key in keys):
        raise ValueError("Every production key must contain exactly 32 hexadecimal characters")
    if len({key.lower() for key in keys}) != 5:
        raise ValueError("All five production keys must be distinct")


def validate_step_order() -> None:
    actions = [step.action for step in PROVISIONING_STEPS]
    admin_change = actions.index("Replace administration key 0 last")
    if admin_change != len(actions) - 2:
        raise ValueError("Administration key 0 is not scheduled last")
    for step in PROVISIONING_STEPS[2:5]:
        if step.recovery_checkpoint != "Factory key 0 retained":
            raise ValueError("A recovery checkpoint is missing before key 0 replacement")


def safety_check(tag_id: str, expected_uid: str) -> None:
    uid = normalise_uid(expected_uid)
    validate_production_keys()
    validate_step_order()

    plan = build_plan(tag_id)
    settings = build_change_file_settings_data(plan)
    if settings != EXPECTED_SETTINGS:
        raise ValueError("FUR ChangeFileSettings profile does not match the locked value")

    print("FUR NTAG 424 DNA — OFFLINE PROVISIONING GATE")
    print("Reader access: DISABLED")
    print("Tag writes: DISABLED")
    print(f"Expected UID: {uid}")
    print(f"Tag ID: {plan.tag_id}")
    print("Five unique production keys: VERIFIED")
    print(f"Locked ChangeFileSettings data: {settings.hex().upper()}")
    for step in PROVISIONING_STEPS:
        print(f"{step.number}. {step.action} [{step.recovery_checkpoint}]")
    print("SAFETY GATE PASSED — EXECUTION REMAINS DISABLED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-id", default="FUR-000001")
    parser.add_argument("--expected-uid", required=True)
    args = parser.parse_args()

    try:
        safety_check(args.tag_id, args.expected_uid)
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"SAFETY GATE FAILED — {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Stateful simulated provisioning executor for FUR NTAG 424 DNA.

The simulator exercises the complete recovery-safe provisioning sequence using
the production keys from macOS Keychain. It has no reader integration and no
APDU transmission capability; physical execution remains unavailable.
"""

import argparse
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntag424_dry_run import (
    PLACEHOLDERS,
    build_change_file_settings_data,
    build_plan,
)
from ntag424_ev2_validate import aes_cmac, truncate_mac
from ntag424_provision import (
    EXPECTED_SETTINGS,
    KEYCHAIN_SERVICES,
    normalise_uid,
)

FACTORY_KEY = bytes(16)
FACTORY_FILE_SETTINGS = bytes.fromhex("0000E0EE000100")
CHECKPOINTS = (
    "preflight_verified",
    "keys_1_to_4_verified",
    "ndef_readback_verified",
    "sdm_settings_readback_verified",
    "key_0_changed",
    "production_auth_and_sun_verified",
)


@dataclass
class SimulatedTag:
    uid: bytes
    keys: Dict[int, bytes] = field(
        default_factory=lambda: {number: FACTORY_KEY for number in range(5)}
    )
    ndef_file: bytes = b""
    file_settings: bytes = FACTORY_FILE_SETTINGS
    authenticated_key: Optional[int] = None
    sdm_counter: int = 0

    def authenticate(self, key_number: int, key: bytes) -> None:
        if key_number not in self.keys or self.keys[key_number] != key:
            raise RuntimeError(f"Authentication failed for key {key_number}")
        self.authenticated_key = key_number

    def change_key(self, key_number: int, old_key: bytes, new_key: bytes) -> None:
        if self.authenticated_key != 0:
            raise RuntimeError("Key changes require administration key 0")
        if self.keys[key_number] != old_key:
            raise RuntimeError(f"Old key {key_number} does not match")
        if len(new_key) != 16:
            raise ValueError("New AES key must contain 16 bytes")
        self.keys[key_number] = new_key
        if key_number == 0:
            self.authenticated_key = None

    def write_ndef(self, data: bytes) -> None:
        if self.authenticated_key != 0:
            raise RuntimeError("NDEF writing requires administration key 0")
        if len(data) > 256:
            raise ValueError("NDEF data exceeds file capacity")
        self.ndef_file = bytes(data)

    def change_file_settings(self, settings: bytes) -> None:
        if self.authenticated_key != 0:
            raise RuntimeError("File-settings changes require administration key 0")
        if settings != EXPECTED_SETTINGS:
            raise ValueError("Settings do not match the locked FUR profile")
        self.file_settings = bytes(settings)

    def read_ndef(self) -> bytes:
        return self.ndef_file

    def read_file_settings(self) -> bytes:
        return self.file_settings

    def generate_sun(self) -> Tuple[str, str, str]:
        if self.file_settings != EXPECTED_SETTINGS:
            raise RuntimeError("SDM is not configured")
        self.sdm_counter += 1
        counter = self.sdm_counter.to_bytes(3, "little")
        sv2 = bytes.fromhex("3CC300010080") + self.uid + counter
        session_mac_key = aes_cmac(self.keys[1], sv2)
        mac = truncate_mac(aes_cmac(session_mac_key, b""))
        return (
            self.uid.hex().upper(),
            counter[::-1].hex().upper(),
            mac.hex().upper(),
        )


@dataclass
class ProvisioningJournal:
    entries: List[str] = field(default_factory=list)

    def record(self, checkpoint: str) -> None:
        expected = CHECKPOINTS[len(self.entries)]
        if checkpoint != expected:
            raise RuntimeError(
                f"Journal expected {expected}, not {checkpoint}"
            )
        self.entries.append(checkpoint)

    @property
    def status(self) -> str:
        if len(self.entries) == len(CHECKPOINTS):
            return "COMPLETE"
        if self.entries and self.entries[-1] == "key_0_changed":
            return "RECOVERY REQUIRED WITH PRODUCTION KEY 0"
        return f"STOPPED SAFELY BEFORE {CHECKPOINTS[len(self.entries)]}"


def keychain_value(service: str) -> bytes:
    account = subprocess.check_output(["id", "-un"], text=True).strip()
    value = subprocess.check_output(
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
    if re.fullmatch(r"[0-9A-Fa-f]{32}", value) is None:
        raise ValueError(f"Keychain item {service} is not a 16-byte AES key")
    return bytes.fromhex(value)


def load_production_keys() -> Dict[int, bytes]:
    keys = {
        number: keychain_value(service)
        for number, service in enumerate(KEYCHAIN_SERVICES)
    }
    if len(set(keys.values())) != 5:
        raise ValueError("All five production keys must be unique")
    return keys


def verify_sun(
    uid_hex: str,
    counter_hex: str,
    mac_hex: str,
    sdm_key: bytes,
) -> None:
    uid = bytes.fromhex(uid_hex)
    mirrored_counter = bytes.fromhex(counter_hex)
    received = bytes.fromhex(mac_hex)
    if len(uid) != 7 or len(mirrored_counter) != 3 or len(received) != 8:
        raise ValueError("SUN fields have invalid lengths")
    # NTAG 424 mirrors the counter as human-readable hexadecimal in MSB-first
    # display order (for example 000001), while the session-vector counter is
    # the three-byte LSB-first value defined by AN12196 (010000).
    counter = mirrored_counter[::-1]
    session_key = aes_cmac(
        sdm_key,
        bytes.fromhex("3CC300010080") + uid + counter,
    )
    expected = truncate_mac(aes_cmac(session_key, b""))
    if received != expected:
        raise RuntimeError("Simulated SUN verification failed")


def maybe_interrupt(checkpoint: str, fail_after: Optional[str]) -> None:
    if fail_after == checkpoint:
        raise RuntimeError(f"SIMULATED INTERRUPTION AFTER {checkpoint}")


def provision_simulated_tag(
    tag: SimulatedTag,
    tag_id: str,
    expected_uid: str,
    production_keys: Dict[int, bytes],
    fail_after: Optional[str] = None,
) -> ProvisioningJournal:
    expected = bytes.fromhex(normalise_uid(expected_uid))
    if tag.uid != expected:
        raise RuntimeError("Preflight UID mismatch")
    if tag.read_file_settings() != FACTORY_FILE_SETTINGS:
        raise RuntimeError("Preflight factory settings mismatch")
    if set(production_keys) != set(range(5)):
        raise ValueError("Production key set must contain keys 0 through 4")
    if len(set(production_keys.values())) != 5:
        raise ValueError("Production keys must be unique")

    plan = build_plan(tag_id)
    settings = build_change_file_settings_data(plan)
    if settings != EXPECTED_SETTINGS:
        raise RuntimeError("Locked FUR settings mismatch")

    journal = ProvisioningJournal()
    tag.authenticate(0, FACTORY_KEY)
    journal.record("preflight_verified")
    maybe_interrupt("preflight_verified", fail_after)

    for key_number in range(1, 5):
        tag.authenticate(0, FACTORY_KEY)
        tag.change_key(key_number, FACTORY_KEY, production_keys[key_number])
        tag.authenticate(key_number, production_keys[key_number])
    tag.authenticate(0, FACTORY_KEY)
    journal.record("keys_1_to_4_verified")
    maybe_interrupt("keys_1_to_4_verified", fail_after)

    tag.write_ndef(plan.ndef_file)
    if tag.read_ndef() != plan.ndef_file:
        raise RuntimeError("NDEF read-back verification failed")
    journal.record("ndef_readback_verified")
    maybe_interrupt("ndef_readback_verified", fail_after)

    tag.change_file_settings(settings)
    if tag.read_file_settings() != settings:
        raise RuntimeError("SDM settings read-back verification failed")
    journal.record("sdm_settings_readback_verified")
    maybe_interrupt("sdm_settings_readback_verified", fail_after)

    tag.change_key(0, FACTORY_KEY, production_keys[0])
    journal.record("key_0_changed")
    maybe_interrupt("key_0_changed", fail_after)

    tag.authenticate(0, production_keys[0])
    uid_hex, counter_hex, mac_hex = tag.generate_sun()
    verify_sun(uid_hex, counter_hex, mac_hex, production_keys[1])
    journal.record("production_auth_and_sun_verified")
    return journal


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--tag-id", default="FUR-000001")
    parser.add_argument("--expected-uid", required=True)
    args = parser.parse_args()

    if not args.simulate:
        print("EXECUTION BLOCKED — ONLY --simulate IS AVAILABLE")
        return 1

    try:
        keys = load_production_keys()
        tag = SimulatedTag(uid=bytes.fromhex(normalise_uid(args.expected_uid)))
        journal = provision_simulated_tag(
            tag,
            args.tag_id,
            args.expected_uid,
            keys,
        )
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"SIMULATION STOPPED — {error}")
        return 1

    print("FUR NTAG 424 DNA — COMPLETE PROVISIONING SIMULATION")
    print("Reader access: DISABLED")
    print("Physical tag writes: DISABLED")
    print("Five production keys: INSTALLED AND VERIFIED IN SIMULATION")
    print("FUR NDEF payload: WRITTEN AND READ BACK IN SIMULATION")
    print("FUR SDM settings: APPLIED AND READ BACK IN SIMULATION")
    print("Administration key 0: CHANGED LAST AND RE-AUTHENTICATED")
    print("SUN generation and verification: PASSED")
    print(f"Recovery journal: {journal.status}")
    print("SIMULATED PROVISIONING PASSED — NO PHYSICAL TAG WAS ACCESSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

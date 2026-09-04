#!/usr/bin/env python3
"""Offline NTAG 424 DNA SUN provisioning planner for FUR.

This program does not connect to a smartcard reader and contains no APDU
transmission code. It validates local prerequisites, builds the NDEF payload,
and calculates the exact ChangeFileSettings command data for review.
"""

import argparse
import re
import subprocess
from dataclasses import dataclass
from typing import Dict

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

BASE_URL = "https://fur-main.vercel.app/result.html"
KEYCHAIN_SERVICE = "FUR SUN SDM Key"
PLACEHOLDERS = {
    "uid": "00000000000000",
    "ctr": "000000",
    "cmac": "0000000000000000",
}

# FUR SDM profile, per the NTAG 424 DNA data sheet:
# plain communication + SDM enabled; key 0 controls writes/settings;
# UID/counter mirrored as ASCII; SUN CMAC uses application key 1.
FILE_OPTION = bytes.fromhex("40")
ACCESS_RIGHTS = bytes.fromhex("00E0")
SDM_OPTIONS = bytes.fromhex("C1")
SDM_ACCESS_RIGHTS = bytes.fromhex("F0E1")
NDEF_FILE_CAPACITY = 256

NXP_TEST_KEY = "5ACE7E50AB65D5D51FD5BF5A16B8205B"
NXP_TEST_SV2 = "3CC30001008004C767F2066180010000"
NXP_TEST_CMAC = "3A3E8110E05311F7A3FCF0D969BF2B48"


@dataclass(frozen=True)
class Plan:
    tag_id: str
    url: str
    ndef_file: bytes
    offsets: Dict[str, int]


def keychain_key_is_valid() -> bool:
    account = subprocess.check_output(["id", "-un"], text=True).strip()
    value = subprocess.check_output(
        [
            "security",
            "find-generic-password",
            "-a",
            account,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
        ],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
    return re.fullmatch(r"[0-9A-Fa-f]{32}", value) is not None


def nxp_cmac_self_test() -> bool:
    cmac = CMAC.new(bytes.fromhex(NXP_TEST_KEY), ciphermod=AES)
    cmac.update(bytes.fromhex(NXP_TEST_SV2))
    return cmac.hexdigest().upper() == NXP_TEST_CMAC


def build_ndef_uri(url: str) -> bytes:
    prefix = "https://"
    if not url.startswith(prefix):
        raise ValueError("FUR URL must use HTTPS")

    encoded_uri = url[len(prefix) :].encode("ascii")
    payload = b"\x04" + encoded_uri
    if len(payload) > 255:
        raise ValueError("URI is too long for a short NDEF record")

    record = bytes([0xD1, 0x01, len(payload)]) + b"U" + payload
    return len(record).to_bytes(2, "big") + record


def build_plan(tag_id: str) -> Plan:
    tag_id = tag_id.strip().upper()
    if re.fullmatch(r"FUR-\d{6}", tag_id) is None:
        raise ValueError("Tag ID must use the format FUR-000001")

    url = (
        f"{BASE_URL}?tagId={tag_id}"
        f"&uid={PLACEHOLDERS['uid']}"
        f"&ctr={PLACEHOLDERS['ctr']}"
        f"&cmac={PLACEHOLDERS['cmac']}"
    )
    ndef_file = build_ndef_uri(url)
    offsets = {}

    for name, placeholder in PLACEHOLDERS.items():
        marker = f"{name}={placeholder}".encode("ascii")
        field_start = ndef_file.find(marker)
        if field_start < 0 or ndef_file.find(marker, field_start + 1) >= 0:
            raise ValueError(f"{name} field must occur exactly once")
        offsets[name] = field_start + len(name) + 1

    return Plan(tag_id=tag_id, url=url, ndef_file=ndef_file, offsets=offsets)


def le24_bytes(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("SDM offset is outside the 24-bit range")
    return value.to_bytes(3, "little")


def le24(value: int) -> str:
    return le24_bytes(value).hex().upper()


def build_change_file_settings_data(plan: Plan) -> bytes:
    if len(plan.ndef_file) > NDEF_FILE_CAPACITY:
        raise ValueError("NDEF payload exceeds the 256-byte file capacity")

    ranges = []
    for name, placeholder in PLACEHOLDERS.items():
        if name not in plan.offsets:
            raise ValueError(f"{name} offset is missing")
        start = plan.offsets[name]
        end = start + len(placeholder)
        if start < 0 or end > len(plan.ndef_file):
            raise ValueError(f"{name} placeholder is outside the NDEF payload")
        expected = placeholder.encode("ascii")
        if plan.ndef_file[start:end] != expected:
            raise ValueError(f"{name} offset does not point to its placeholder")
        ranges.append((start, end, name))

    ordered = sorted(ranges)
    for previous, current in zip(ordered, ordered[1:]):
        if previous[1] > current[0]:
            raise ValueError(f"{previous[2]} and {current[2]} placeholders overlap")

    cmac_end = plan.offsets["cmac"] + len(PLACEHOLDERS["cmac"])
    if cmac_end != len(plan.ndef_file):
        raise ValueError("CMAC placeholder must end at the NDEF payload boundary")

    uid = le24_bytes(plan.offsets["uid"])
    ctr = le24_bytes(plan.offsets["ctr"])
    mac = le24_bytes(plan.offsets["cmac"])
    return (
        FILE_OPTION
        + ACCESS_RIGHTS
        + SDM_OPTIONS
        + SDM_ACCESS_RIGHTS
        + uid
        + ctr
        + mac
        + mac
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-id", default="FUR-000001")
    args = parser.parse_args()

    print("FUR NTAG 424 DNA — OFFLINE DRY RUN")
    print("Reader access: DISABLED")
    print("Tag writes: DISABLED")

    if not keychain_key_is_valid():
        print("Keychain key: INVALID")
        return 1
    print("Keychain key: READY")

    if not nxp_cmac_self_test():
        print("NXP AES-CMAC self-test: FAILED")
        return 1
    print("NXP AES-CMAC self-test: PASSED")

    try:
        plan = build_plan(args.tag_id)
        settings_data = build_change_file_settings_data(plan)
    except ValueError as error:
        print(f"Plan: INVALID — {error}")
        return 1

    print(f"Tag ID: {plan.tag_id}")
    print(f"NDEF URL template: {plan.url}")
    print(f"NDEF file length: {len(plan.ndef_file)} bytes")
    print(
        "SDM offsets (decimal / 3-byte little-endian): "
        f"UID {plan.offsets['uid']} / {le24(plan.offsets['uid'])}, "
        f"CTR {plan.offsets['ctr']} / {le24(plan.offsets['ctr'])}, "
        f"MAC input {plan.offsets['cmac']} / {le24(plan.offsets['cmac'])}, "
        f"CMAC {plan.offsets['cmac']} / {le24(plan.offsets['cmac'])}"
    )
    print(f"FUR ChangeFileSettings data: {settings_data.hex().upper()}")
    print("PROFILE VALIDATED — NO READER OR TAG WAS ACCESSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

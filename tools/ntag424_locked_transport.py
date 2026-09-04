#!/usr/bin/env python3
"""Fail-closed transport gate for the future FUR NTAG 424 live executor.

This module validates every mutating command builder but deliberately refuses
to transmit one. It is the final transport boundary before reviewed live
execution is enabled.
"""

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntag424_auth_key_validate import (
    EXPECTED_DIFFERENT_APDU,
    EXPECTED_SAME_APDU,
    change_authenticated_key_apdu,
    change_other_key_apdu,
    validate_change_key_vectors,
    CHANGE_ENC_KEY,
    CHANGE_MAC_KEY,
    CHANGE_TI,
    DIFFERENT_NEW_KEY,
    SAME_NEW_KEY,
    ZERO_KEY,
)
from ntag424_ev2_validate import protect_command, validate_nxp_table_18
from ntag424_provision import EXPECTED_SETTINGS, validate_step_order
from ntag424_write_validate import (
    EXPECTED_RESPONSE,
    EXPECTED_WRITE_APDU,
    NXP_WRITE_DATA,
    SESSION_ENC_KEY,
    SESSION_MAC_KEY,
    TI,
    build_write_data_apdu,
    validate_nxp_write_vector,
    verify_protected_response,
)

MUTATING_INS = {0x3D, 0x5F, 0x8D, 0xC4, 0xD6}


class LockedTransport:
    def transmit(self, apdu):
        if len(apdu) < 2:
            raise ValueError("APDU is too short")
        if int(apdu[1]) in MUTATING_INS:
            raise PermissionError("Persistent tag mutation is locked")
        raise PermissionError("Reader access is disabled in transport-gate mode")


def build_change_file_settings_apdu() -> bytes:
    return protect_command(
        0x5F,
        bytes([2]),
        EXPECTED_SETTINGS,
        SESSION_ENC_KEY,
        SESSION_MAC_KEY,
        TI,
        1,
    ).apdu


def safety_check() -> None:
    validate_nxp_table_18()
    validate_change_key_vectors()
    validate_nxp_write_vector()
    validate_step_order()

    if build_write_data_apdu(
        NXP_WRITE_DATA, SESSION_ENC_KEY, SESSION_MAC_KEY, TI, 0
    ) != EXPECTED_WRITE_APDU:
        raise RuntimeError("WriteData command builder changed")
    verify_protected_response(EXPECTED_RESPONSE, 0, TI, SESSION_MAC_KEY)
    if change_other_key_apdu(
        2, ZERO_KEY, DIFFERENT_NEW_KEY, 1, 2,
        CHANGE_ENC_KEY, CHANGE_MAC_KEY, CHANGE_TI,
    ) != EXPECTED_DIFFERENT_APDU:
        raise RuntimeError("Different-key ChangeKey builder changed")
    if change_authenticated_key_apdu(
        0, SAME_NEW_KEY, 1, 3,
        CHANGE_ENC_KEY, CHANGE_MAC_KEY, CHANGE_TI,
    ) != EXPECTED_SAME_APDU:
        raise RuntimeError("Administration-key ChangeKey builder changed")

    guarded = LockedTransport()
    for instruction in MUTATING_INS:
        try:
            guarded.transmit([0x90, instruction])
        except PermissionError:
            continue
        raise RuntimeError(f"Mutation instruction {instruction:02X} escaped the lock")


def main() -> int:
    print("FUR NTAG 424 DNA — LOCKED TRANSPORT SAFETY CHECK")
    print("Reader access: DISABLED")
    print("Persistent tag writes: BLOCKED")
    try:
        safety_check()
    except (PermissionError, RuntimeError, ValueError) as error:
        print(f"TRANSPORT GATE FAILED — {error}")
        return 1
    print("NXP protected WriteData and response MAC: VERIFIED")
    print("NXP ChangeFileSettings secure messaging: VERIFIED")
    print("NXP ChangeKey cases and key-0-last order: VERIFIED")
    print("TRANSPORT GATE PASSED — LIVE EXECUTION REMAINS LOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

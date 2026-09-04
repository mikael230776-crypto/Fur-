#!/usr/bin/env python3
"""Offline WriteData, response-MAC and interruption-safety validator.

No reader integration or APDU transmission is present. Cryptographic results
are checked against NXP AN12196 Rev. 2.0 Table 17.
"""

import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntag424_ev2_validate import aes_cmac, protect_command, truncate_mac

SESSION_ENC_KEY = bytes.fromhex("1309C877509E5A215007FF0ED19CA564")
SESSION_MAC_KEY = bytes.fromhex("4C6626F5E72EA694202139295C7A7FC7")
TI = bytes.fromhex("9D00C4DF")
FILE_NUMBER = 2
COMMAND_COUNTER = 0

NXP_WRITE_DATA = bytes.fromhex(
    "0051D1014D550463686F6F73652E75726C2E636F6D2F6E7461673432343F"
    "653D3030303030303030303030303030303030303030303030303030303030"
    "303026633D30303030303030303030303030303030"
    "000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000"
)
EXPECTED_WRITE_APDU = bytes.fromhex(
    "908D00009F02000000800000"
    "421C73A27D827658AF481FDFF20A5025B559D0E3AA21E58D347F343CFFC768B"
    "FE596C706BC00F2176781D4B0242642A0FF5A42C461AAF894D9A1284B8C76BC"
    "FA658ACD40555D362E08DB15CF421B51283F9064BCBE20E96CAE545B407C9D"
    "651A3315B27373772E5DA2367D2064AE054AF996C6F1F669170FA88CE8C4E3"
    "A4A7BBBEF0FD971FF532C3A802AF745660F2B4"
    "D1D9A8499661EBF300"
)
EXPECTED_RESPONSE = bytes.fromhex("FC222E5F7A5424529100")

CHECKPOINTS = (
    "preflight_verified",
    "keys_1_to_4_verified",
    "ndef_readback_verified",
    "sdm_settings_readback_verified",
    "key_0_changed",
    "production_auth_and_sun_verified",
)


@dataclass(frozen=True)
class JournalEntry:
    checkpoint: str
    verified: bool


def le24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("Value does not fit in three bytes")
    return value.to_bytes(3, "little")


def build_write_data_apdu(
    data: bytes,
    session_enc_key: bytes,
    session_mac_key: bytes,
    ti: bytes,
    command_counter: int,
    file_number: int = FILE_NUMBER,
) -> bytes:
    if not 0 <= file_number <= 0x1F:
        raise ValueError("File number is out of range")
    header = bytes([file_number]) + le24(0) + le24(len(data))
    return protect_command(
        0x8D,
        header,
        data,
        session_enc_key,
        session_mac_key,
        ti,
        command_counter,
    ).apdu


def response_mac(
    response_code: int,
    next_command_counter: int,
    ti: bytes,
    response_data: bytes,
    session_mac_key: bytes,
) -> bytes:
    if not 0 <= response_code <= 0xFF:
        raise ValueError("Response code is out of range")
    if len(ti) != 4:
        raise ValueError("Transaction identifier must contain four bytes")
    if not 0 <= next_command_counter <= 0xFFFF:
        raise ValueError("Command counter is out of range")
    message = (
        bytes([response_code])
        + next_command_counter.to_bytes(2, "little")
        + ti
        + response_data
    )
    return truncate_mac(aes_cmac(session_mac_key, message))


def verify_protected_response(
    response: bytes,
    command_counter: int,
    ti: bytes,
    session_mac_key: bytes,
) -> None:
    if len(response) < 10:
        raise ValueError("Protected response is too short")
    body, sw1, sw2 = response[:-2], response[-2], response[-1]
    if (sw1, sw2) != (0x91, 0x00):
        raise ValueError(f"Tag returned status {sw1:02X}{sw2:02X}")
    response_data, received_mac = body[:-8], body[-8:]
    expected_mac = response_mac(
        0x00,
        command_counter + 1,
        ti,
        response_data,
        session_mac_key,
    )
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("Protected response MAC is invalid")


def validate_journal(entries: Sequence[JournalEntry]) -> str:
    if len(entries) > len(CHECKPOINTS):
        raise ValueError("Journal contains too many checkpoints")
    for index, entry in enumerate(entries):
        if entry.checkpoint != CHECKPOINTS[index]:
            raise ValueError("Journal skipped or reordered a checkpoint")
        if not entry.verified:
            raise ValueError(f"Checkpoint {entry.checkpoint} is not verified")
    if entries and entries[-1].checkpoint == "key_0_changed":
        return "RECOVERY REQUIRED: authenticate with production key 0"
    if len(entries) == len(CHECKPOINTS):
        return "COMPLETE"
    return f"STOPPED SAFELY: next checkpoint is {CHECKPOINTS[len(entries)]}"


def validate_nxp_write_vector() -> None:
    if len(NXP_WRITE_DATA) != 128:
        raise ValueError("NXP WriteData length is not 128 bytes")
    apdu = build_write_data_apdu(
        NXP_WRITE_DATA,
        SESSION_ENC_KEY,
        SESSION_MAC_KEY,
        TI,
        COMMAND_COUNTER,
    )
    if apdu != EXPECTED_WRITE_APDU:
        raise ValueError("NXP protected WriteData vector failed")
    verify_protected_response(
        EXPECTED_RESPONSE,
        COMMAND_COUNTER,
        TI,
        SESSION_MAC_KEY,
    )


def main() -> int:
    print("FUR NTAG 424 DNA — OFFLINE WRITE/RESPONSE VALIDATION")
    print("Reader access: DISABLED")
    print("Tag writes: DISABLED")
    try:
        validate_nxp_write_vector()
        print("NXP protected WriteData vector: PASSED")
        print("NXP protected response MAC: PASSED")
        journal_result = validate_journal(
            [
                JournalEntry("preflight_verified", True),
                JournalEntry("keys_1_to_4_verified", True),
                JournalEntry("ndef_readback_verified", True),
                JournalEntry("sdm_settings_readback_verified", True),
            ]
        )
        if not journal_result.startswith("STOPPED SAFELY"):
            raise ValueError("Interruption journal did not fail closed")
        print("Interruption recovery journal: PASSED")
    except ValueError as error:
        print(f"OFFLINE VALIDATION FAILED — {error}")
        return 1
    print("PROTECTED WRITE AND RECOVERY MATH READY — NO TAG WAS ACCESSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

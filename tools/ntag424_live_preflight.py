#!/usr/bin/env python3
"""Safety-locked live preflight for a factory-state FUR NTAG 424 DNA.

The default mode does not access a reader. Explicit --preflight permits only
identity/configuration reads and AuthenticateEV2First. No persistent tag
mutation command is allowlisted or constructed by this utility.
"""

import argparse
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from Crypto.Cipher import AES

from ntag424_auth_key_validate import (
    derive_session_keys,
    rotate_left,
    rotate_right,
)
from ntag424_provision import normalise_uid

NDEF_APPLICATION = bytes.fromhex("D2760000850101")
FACTORY_KEY_0 = bytes(16)
EXPECTED_FACTORY_FILE_SETTINGS = bytes.fromhex("0000E0EE000100")

ALLOWED_COMMANDS = {
    (0xFF, 0xCA): "reader UID",
    (0x00, 0xA4): "ISO SELECT",
    (0x90, 0x60): "GetVersion",
    (0x90, 0xAF): "AdditionalFrame",
    (0x90, 0xF5): "GetFileSettings",
    (0x90, 0x71): "AuthenticateEV2First",
}
MUTATING_INSTRUCTIONS = {
    0x3D: "WriteData",
    0x5F: "ChangeFileSettings",
    0x8D: "WriteData secure",
    0xC4: "ChangeKey",
    0xD6: "ISO UPDATE BINARY",
}


@dataclass(frozen=True)
class PreflightSession:
    ti: bytes
    session_enc_key: bytes
    session_mac_key: bytes


def require_preflight_command(apdu: Sequence[int]) -> str:
    if len(apdu) < 2:
        raise ValueError("APDU is too short")
    cla, ins = int(apdu[0]), int(apdu[1])
    if ins in MUTATING_INSTRUCTIONS:
        raise PermissionError(f"Persistent mutation blocked: {MUTATING_INSTRUCTIONS[ins]}")
    label = ALLOWED_COMMANDS.get((cla, ins))
    if label is None:
        raise PermissionError(f"APDU {cla:02X}{ins:02X} is not preflight-allowlisted")
    return label


def transmit(connection, apdu: Sequence[int]) -> Tuple[bytes, int, int]:
    require_preflight_command(apdu)
    data, sw1, sw2 = connection.transmit(list(apdu))
    return bytes(data), sw1, sw2


def expect_status(
    result: Tuple[bytes, int, int],
    expected_status: Tuple[int, int],
    label: str,
) -> bytes:
    data, sw1, sw2 = result
    if (sw1, sw2) != expected_status:
        raise RuntimeError(f"{label} failed: {sw1:02X}{sw2:02X}")
    return data


def select_ndef_application(connection) -> None:
    apdu = [0x00, 0xA4, 0x04, 0x00, len(NDEF_APPLICATION), *NDEF_APPLICATION, 0x00]
    expect_status(transmit(connection, apdu), (0x90, 0x00), "NDEF application selection")


def read_uid(connection) -> bytes:
    return expect_status(
        transmit(connection, [0xFF, 0xCA, 0x00, 0x00, 0x00]),
        (0x90, 0x00),
        "UID read",
    )


def get_version(connection) -> bytes:
    collected = bytearray()
    result = transmit(connection, [0x90, 0x60, 0x00, 0x00, 0x00])
    while True:
        data, sw1, sw2 = result
        collected.extend(data)
        if (sw1, sw2) == (0x91, 0x00):
            return bytes(collected)
        if (sw1, sw2) != (0x91, 0xAF):
            raise RuntimeError(f"GetVersion failed: {sw1:02X}{sw2:02X}")
        result = transmit(connection, [0x90, 0xAF, 0x00, 0x00, 0x00])


def get_file_settings(connection, file_number: int = 2) -> bytes:
    if file_number != 2:
        raise ValueError("Preflight is locked to NDEF file number 2")
    apdu = [0x90, 0xF5, 0x00, 0x00, 0x01, file_number, 0x00]
    return expect_status(
        transmit(connection, apdu),
        (0x91, 0x00),
        "GetFileSettings",
    )


def validate_version(version: bytes, uid: bytes) -> None:
    if len(version) != 28:
        raise RuntimeError("Unexpected NTAG version-data length")
    if version[0:2] != bytes.fromhex("0404") or version[7:9] != bytes.fromhex("0404"):
        raise RuntimeError("Version data does not identify an NXP NTAG")
    if version[14:21] != uid:
        raise RuntimeError("Version UID does not match the reader UID")


def authenticate_ev2_first_with_key(
    connection,
    key_number: int,
    static_key: bytes,
    rnd_a: bytes = None,
) -> PreflightSession:
    if not 0 <= key_number <= 4:
        raise ValueError("Key number must be between 0 and 4")
    if len(static_key) != 16:
        raise ValueError("Static AES key must contain 16 bytes")
    if rnd_a is None:
        rnd_a = secrets.token_bytes(16)
    if len(rnd_a) != 16:
        raise ValueError("RndA must contain 16 bytes")

    encrypted_rnd_b = expect_status(
        transmit(connection, [0x90, 0x71, 0x00, 0x00, 0x02, key_number, 0x00, 0x00]),
        (0x91, 0xAF),
        "AuthenticateEV2First part 1",
    )
    if len(encrypted_rnd_b) != 16:
        raise RuntimeError("AuthenticateEV2First returned an invalid RndB length")
    rnd_b = AES.new(static_key, AES.MODE_CBC, iv=bytes(16)).decrypt(encrypted_rnd_b)

    challenge = rnd_a + rotate_left(rnd_b)
    encrypted_challenge = AES.new(
        static_key,
        AES.MODE_CBC,
        iv=bytes(16),
    ).encrypt(challenge)
    response_apdu = [
        0x90,
        0xAF,
        0x00,
        0x00,
        len(encrypted_challenge),
        *encrypted_challenge,
        0x00,
    ]
    encrypted_response = expect_status(
        transmit(connection, response_apdu),
        (0x91, 0x00),
        "AuthenticateEV2First part 2",
    )
    if len(encrypted_response) != 32:
        raise RuntimeError("AuthenticateEV2First returned an invalid response length")
    response = AES.new(
        static_key,
        AES.MODE_CBC,
        iv=bytes(16),
    ).decrypt(encrypted_response)

    ti, rotated_a, capabilities = response[:4], response[4:20], response[20:]
    if rotate_right(rotated_a) != rnd_a:
        raise RuntimeError("AuthenticateEV2First challenge verification failed")
    if len(ti) != 4 or len(capabilities) != 12:
        raise RuntimeError("AuthenticateEV2First response structure is invalid")

    session_enc_key, session_mac_key = derive_session_keys(static_key, rnd_a, rnd_b)
    return PreflightSession(ti, session_enc_key, session_mac_key)


def authenticate_ev2_first(
    connection,
    rnd_a: bytes = None,
    key_number: int = 0,
    static_key: bytes = FACTORY_KEY_0,
) -> PreflightSession:
    if key_number != 0 or static_key != FACTORY_KEY_0:
        raise ValueError("Live preflight is locked to factory key 0")
    return authenticate_ev2_first_with_key(connection, key_number, static_key, rnd_a)


def find_picc_reader():
    from smartcard.System import readers

    matches = [
        reader
        for reader in readers()
        if "ACR1552" in str(reader).upper() and "PICC" in str(reader).upper()
    ]
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one ACR1552 PICC reader; found {len(matches)}")
    return matches[0]


def run_live_preflight(expected_uid: str) -> None:
    expected = bytes.fromhex(normalise_uid(expected_uid))
    reader = find_picc_reader()
    connection = reader.createConnection()
    connection.connect()

    uid = read_uid(connection)
    if uid != expected:
        raise RuntimeError(
            f"STOP: reader UID {uid.hex().upper()} does not match expected UID "
            f"{expected.hex().upper()}"
        )

    select_ndef_application(connection)
    version = get_version(connection)
    validate_version(version, uid)

    settings = get_file_settings(connection)
    if settings != EXPECTED_FACTORY_FILE_SETTINGS:
        raise RuntimeError(
            "STOP: NDEF file is not in the expected factory configuration "
            f"({settings.hex().upper()})"
        )

    authenticate_ev2_first(connection)
    print(f"Reader: {reader}")
    print(f"UID: {uid.hex().upper()} — MATCHED")
    print(f"Version: NTAG 424 DNA — VERIFIED")
    print(f"Factory NDEF settings: {settings.hex().upper()} — VERIFIED")
    print("Factory key 0 authentication: VERIFIED")
    print("LIVE PREFLIGHT PASSED — NO PERSISTENT TAG DATA WAS CHANGED")


def safety_check() -> None:
    for command in ALLOWED_COMMANDS:
        require_preflight_command(command)
    for instruction in MUTATING_INSTRUCTIONS:
        try:
            require_preflight_command([0x90, instruction])
        except PermissionError:
            continue
        raise RuntimeError(f"Mutation instruction {instruction:02X} was unexpectedly allowed")
    print("FUR NTAG 424 DNA — LIVE PREFLIGHT SAFETY CHECK")
    print("Reader access: DISABLED")
    print("Persistent tag writes: BLOCKED")
    print("Allowed operation: identity/configuration reads plus factory authentication")
    print("PREFLIGHT UTILITY READY — NO TAG WAS ACCESSED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--safety-check", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    parser.add_argument("--expected-uid")
    args = parser.parse_args()

    try:
        if args.preflight:
            if not args.expected_uid:
                raise ValueError("--expected-uid is required with --preflight")
            run_live_preflight(args.expected_uid)
        else:
            safety_check()
    except (PermissionError, RuntimeError, ValueError) as error:
        print(f"PREFLIGHT STOPPED — {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline authentication and ChangeKey vector validator for FUR NTAG 424 DNA.

No reader integration or APDU transmission is present. Calculations are checked
against NXP AN12196 Rev. 2.0 Tables 14, 25 and 26.
"""

import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from Crypto.Cipher import AES

from ntag424_ev2_validate import aes_cmac, protect_command

ZERO_KEY = bytes(16)

AUTH_RNDB_ENC = bytes.fromhex("A04C124213C186F22399D33AC2A30215")
AUTH_RNDB = bytes.fromhex("B9E2FC789B64BF237CCCAA20EC7E6E48")
AUTH_RNDA = bytes.fromhex("13C5DB8A5930439FC3DEF9A4C675360F")
AUTH_PART2_ENC = bytes.fromhex(
    "35C3E05A752E0144BAC0DE51C1F22C56"
    "B34408A23D8AEA266CAB947EA8E0118D"
)
AUTH_RESPONSE_ENC = bytes.fromhex(
    "3FA64DB5446D1F34CD6EA311167F5E49"
    "85B89690C04A05F17FA7AB2F08120663"
)
AUTH_TI = bytes.fromhex("9D00C4DF")
AUTH_ENC_KEY = bytes.fromhex("1309C877509E5A215007FF0ED19CA564")
AUTH_MAC_KEY = bytes.fromhex("4C6626F5E72EA694202139295C7A7FC7")

CHANGE_TI = bytes.fromhex("7614281A")
CHANGE_ENC_KEY = bytes.fromhex("4CF3CB41A22583A61E89B158D252FC53")
CHANGE_MAC_KEY = bytes.fromhex("5529860B2FC5FB6154B7F28361D30BF9")
DIFFERENT_NEW_KEY = bytes.fromhex("F3847D627727ED3BC9C4CC050489B966")
SAME_NEW_KEY = bytes.fromhex("5004BF991F408672B1EF00F08F9E8647")
EXPECTED_DIFFERENT_APDU = bytes.fromhex(
    "90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9"
    "E16C2393AE9CD1FAC75D0CE20BCD1D06E600"
)
EXPECTED_SAME_APDU = bytes.fromhex(
    "90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05"
    "053FF75668A01D6FDA6610234BDED643200"
)


@dataclass(frozen=True)
class AuthenticationVector:
    rnd_b: bytes
    part2: bytes
    ti: bytes
    session_enc_key: bytes
    session_mac_key: bytes


def rotate_left(data: bytes) -> bytes:
    if not data:
        raise ValueError("Rotation input must not be empty")
    return data[1:] + data[:1]


def rotate_right(data: bytes) -> bytes:
    if not data:
        raise ValueError("Rotation input must not be empty")
    return data[-1:] + data[:-1]


def session_vectors(rnd_a: bytes, rnd_b: bytes) -> Tuple[bytes, bytes]:
    if len(rnd_a) != 16 or len(rnd_b) != 16:
        raise ValueError("Authentication random values must contain 16 bytes")
    mixed = bytes(a ^ b for a, b in zip(rnd_a[2:8], rnd_b[0:6]))
    common = rnd_a[0:2] + mixed + rnd_b[6:16] + rnd_a[8:16]
    return bytes.fromhex("A55A00010080") + common, bytes.fromhex("5AA500010080") + common


def derive_session_keys(
    static_key: bytes, rnd_a: bytes, rnd_b: bytes
) -> Tuple[bytes, bytes]:
    sv_enc, sv_mac = session_vectors(rnd_a, rnd_b)
    return aes_cmac(static_key, sv_enc), aes_cmac(static_key, sv_mac)


def validate_authentication_vector() -> AuthenticationVector:
    rnd_b = AES.new(ZERO_KEY, AES.MODE_CBC, iv=bytes(16)).decrypt(AUTH_RNDB_ENC)
    if rnd_b != AUTH_RNDB:
        raise ValueError("NXP RndB decryption failed")

    plaintext = AUTH_RNDA + rotate_left(rnd_b)
    part2 = AES.new(ZERO_KEY, AES.MODE_CBC, iv=bytes(16)).encrypt(plaintext)
    if part2 != AUTH_PART2_ENC:
        raise ValueError("NXP authentication part 2 encryption failed")

    response = AES.new(ZERO_KEY, AES.MODE_CBC, iv=bytes(16)).decrypt(
        AUTH_RESPONSE_ENC
    )
    ti, rotated_a = response[:4], response[4:20]
    if ti != AUTH_TI or rotate_right(rotated_a) != AUTH_RNDA:
        raise ValueError("NXP authentication response verification failed")
    if response[20:] != bytes(12):
        raise ValueError("NXP capability bytes are unexpected")

    session_enc, session_mac = derive_session_keys(ZERO_KEY, AUTH_RNDA, rnd_b)
    if session_enc != AUTH_ENC_KEY or session_mac != AUTH_MAC_KEY:
        raise ValueError("NXP session-key derivation failed")
    return AuthenticationVector(rnd_b, part2, ti, session_enc, session_mac)


def desfire_crc32(data: bytes) -> bytes:
    value = (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF
    return value.to_bytes(4, "little")


def change_other_key_apdu(
    key_number: int,
    old_key: bytes,
    new_key: bytes,
    key_version: int,
    command_counter: int,
    session_enc_key: bytes,
    session_mac_key: bytes,
    ti: bytes,
) -> bytes:
    if not 0 <= key_number <= 4:
        raise ValueError("Key number must be between 0 and 4")
    if len(old_key) != 16 or len(new_key) != 16:
        raise ValueError("AES keys must contain 16 bytes")
    if not 0 <= key_version <= 0xFF:
        raise ValueError("Key version must fit in one byte")
    changed = bytes(old ^ new for old, new in zip(old_key, new_key))
    data = changed + bytes([key_version]) + desfire_crc32(new_key)
    return protect_command(
        0xC4,
        bytes([key_number]),
        data,
        session_enc_key,
        session_mac_key,
        ti,
        command_counter,
    ).apdu


def change_authenticated_key_apdu(
    key_number: int,
    new_key: bytes,
    key_version: int,
    command_counter: int,
    session_enc_key: bytes,
    session_mac_key: bytes,
    ti: bytes,
) -> bytes:
    if not 0 <= key_number <= 4:
        raise ValueError("Key number must be between 0 and 4")
    if len(new_key) != 16:
        raise ValueError("AES key must contain 16 bytes")
    if not 0 <= key_version <= 0xFF:
        raise ValueError("Key version must fit in one byte")
    return protect_command(
        0xC4,
        bytes([key_number]),
        new_key + bytes([key_version]),
        session_enc_key,
        session_mac_key,
        ti,
        command_counter,
    ).apdu


def validate_change_key_vectors() -> None:
    if desfire_crc32(DIFFERENT_NEW_KEY) != bytes.fromhex("789DFADC"):
        raise ValueError("NXP ChangeKey CRC32 vector failed")

    different = change_other_key_apdu(
        2,
        ZERO_KEY,
        DIFFERENT_NEW_KEY,
        1,
        2,
        CHANGE_ENC_KEY,
        CHANGE_MAC_KEY,
        CHANGE_TI,
    )
    if different != EXPECTED_DIFFERENT_APDU:
        raise ValueError("NXP different-key ChangeKey vector failed")

    same = change_authenticated_key_apdu(
        0,
        SAME_NEW_KEY,
        1,
        3,
        CHANGE_ENC_KEY,
        CHANGE_MAC_KEY,
        CHANGE_TI,
    )
    if same != EXPECTED_SAME_APDU:
        raise ValueError("NXP authenticated-key ChangeKey vector failed")


def main() -> int:
    print("FUR NTAG 424 DNA — OFFLINE AUTHENTICATION/KEY VALIDATION")
    print("Reader access: DISABLED")
    print("Tag writes: DISABLED")
    try:
        validate_authentication_vector()
        print("NXP AuthenticateEV2First vector: PASSED")
        validate_change_key_vectors()
        print("NXP ChangeKey different-key vector: PASSED")
        print("NXP ChangeKey authenticated-key vector: PASSED")
    except ValueError as error:
        print(f"OFFLINE VALIDATION FAILED — {error}")
        return 1
    print("AUTHENTICATION AND KEY-CHANGE MATH READY — NO TAG WAS ACCESSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

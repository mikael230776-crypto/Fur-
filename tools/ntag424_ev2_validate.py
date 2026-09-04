#!/usr/bin/env python3
"""Offline NTAG 424 DNA EV2 secure-messaging validator for FUR.

This module contains no reader integration and cannot transmit APDUs. It checks
the cryptographic construction against NXP AN12196 Rev. 2.0, Table 18.
"""

from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

BLOCK_SIZE = 16


def aes_cmac(key: bytes, message: bytes) -> bytes:
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES key must contain 16 bytes")
    value = CMAC.new(key, ciphermod=AES)
    value.update(message)
    return value.digest()


def truncate_mac(full_mac: bytes) -> bytes:
    if len(full_mac) != BLOCK_SIZE:
        raise ValueError("Full MAC must contain 16 bytes")
    return full_mac[1::2]


def iso7816_pad(data: bytes) -> bytes:
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + b"\x80" + bytes(padding_length - 1)


def command_iv(session_enc_key: bytes, ti: bytes, command_counter: int) -> bytes:
    if len(ti) != 4:
        raise ValueError("Transaction identifier must contain 4 bytes")
    if not 0 <= command_counter <= 0xFFFF:
        raise ValueError("Command counter is out of range")
    seed = (
        bytes.fromhex("A55A")
        + ti
        + command_counter.to_bytes(2, "little")
        + bytes(8)
    )
    return AES.new(session_enc_key, AES.MODE_ECB).encrypt(seed)


@dataclass(frozen=True)
class ProtectedCommand:
    iv: bytes
    encrypted_data: bytes
    full_mac: bytes
    truncated_mac: bytes
    apdu: bytes


def protect_command(
    command: int,
    header: bytes,
    command_data: bytes,
    session_enc_key: bytes,
    session_mac_key: bytes,
    ti: bytes,
    command_counter: int,
) -> ProtectedCommand:
    iv = command_iv(session_enc_key, ti, command_counter)
    encrypted = AES.new(
        session_enc_key,
        AES.MODE_CBC,
        iv=iv,
    ).encrypt(iso7816_pad(command_data))
    mac_input = (
        bytes([command])
        + command_counter.to_bytes(2, "little")
        + ti
        + header
        + encrypted
    )
    full_mac = aes_cmac(session_mac_key, mac_input)
    truncated = truncate_mac(full_mac)
    body = header + encrypted + truncated
    apdu = bytes([0x90, command, 0x00, 0x00, len(body)]) + body + b"\x00"
    return ProtectedCommand(iv, encrypted, full_mac, truncated, apdu)


def validate_nxp_table_18() -> bool:
    result = protect_command(
        command=0x5F,
        header=bytes.fromhex("02"),
        command_data=bytes.fromhex("4000E0C1F121200000430000430000"),
        session_enc_key=bytes.fromhex("1309C877509E5A215007FF0ED19CA564"),
        session_mac_key=bytes.fromhex("4C6626F5E72EA694202139295C7A7FC7"),
        ti=bytes.fromhex("9D00C4DF"),
        command_counter=1,
    )
    return (
        result.iv.hex().upper() == "3E27082AB2ACC1EF55C57547934E9962"
        and result.encrypted_data.hex().upper()
        == "61B6D97903566E84C3AE5274467E89EA"
        and result.full_mac.hex().upper()
        == "7BD75F991CB7A2C18DA09EEF047A8D04"
        and result.truncated_mac.hex().upper() == "D799B7C1A0EF7A04"
        and result.apdu.hex().upper()
        == "905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400"
    )


def main() -> int:
    print("FUR NTAG 424 DNA — OFFLINE EV2 VALIDATION")
    print("Reader access: DISABLED")
    print("Tag writes: DISABLED")
    if not validate_nxp_table_18():
        print("NXP ChangeFileSettings vector: FAILED")
        return 1
    print("NXP ChangeFileSettings vector: PASSED")
    print("EV2 COMMAND PROTECTION READY — NO TAG WAS ACCESSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

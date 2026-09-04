#!/usr/bin/env python3
"""Strictly read-only NTAG 424 DNA inspector for FUR.

The default --safety-check mode does not access a reader. Card inspection must
be requested explicitly with --inspect. Every APDU is checked against a narrow
read-only allowlist before transmission.
"""

import argparse
from typing import Iterable, List, Sequence, Tuple

READ_ONLY_COMMANDS = {
    (0xFF, 0xCA): "reader UID",
    (0x00, 0xA4): "ISO SELECT",
    (0x00, 0xB0): "ISO READ BINARY",
    (0x90, 0x60): "GetVersion",
    (0x90, 0xAF): "AdditionalFrame",
    (0x90, 0xF5): "GetFileSettings",
}
BLOCKED_INSTRUCTIONS = {
    0x3D: "WriteData",
    0x5F: "ChangeFileSettings",
    0x71: "AuthenticateEV2First",
    0x77: "AuthenticateEV2NonFirst",
    0x8D: "WriteData secure",
    0xC4: "ChangeKey",
    0xD6: "ISO UPDATE BINARY",
}
NDEF_APPLICATION = bytes.fromhex("D2760000850101")
NDEF_FILE = bytes.fromhex("E104")


def hex_text(data: Iterable[int]) -> str:
    return bytes(data).hex().upper()


def require_read_only(apdu: Sequence[int]) -> str:
    if len(apdu) < 2:
        raise ValueError("APDU is too short")
    cla, ins = int(apdu[0]), int(apdu[1])
    if ins in BLOCKED_INSTRUCTIONS:
        raise PermissionError(f"Blocked command: {BLOCKED_INSTRUCTIONS[ins]}")
    label = READ_ONLY_COMMANDS.get((cla, ins))
    if label is None:
        raise PermissionError(f"APDU {cla:02X}{ins:02X} is not allowlisted")
    return label


def transmit(connection, apdu: Sequence[int]) -> Tuple[bytes, int, int]:
    require_read_only(apdu)
    data, sw1, sw2 = connection.transmit(list(apdu))
    return bytes(data), sw1, sw2


def expect_ok(result: Tuple[bytes, int, int], label: str) -> bytes:
    data, sw1, sw2 = result
    if (sw1, sw2) not in {(0x90, 0x00), (0x91, 0x00)}:
        raise RuntimeError(f"{label} failed: {sw1:02X}{sw2:02X}")
    return data


def select_by_name(connection, name: bytes) -> None:
    apdu = [0x00, 0xA4, 0x04, 0x00, len(name), *name, 0x00]
    expect_ok(transmit(connection, apdu), "NDEF application selection")


def select_file(connection, file_id: bytes) -> None:
    apdu = [0x00, 0xA4, 0x00, 0x0C, len(file_id), *file_id]
    expect_ok(transmit(connection, apdu), f"file {hex_text(file_id)} selection")


def read_binary(connection, offset: int, length: int) -> bytes:
    if not 0 <= offset <= 0xFFFF or not 1 <= length <= 0xF0:
        raise ValueError("READ BINARY range is invalid")
    apdu = [0x00, 0xB0, offset >> 8, offset & 0xFF, length]
    return expect_ok(transmit(connection, apdu), "READ BINARY")


def read_ndef(connection) -> bytes:
    select_file(connection, NDEF_FILE)
    nlen = int.from_bytes(read_binary(connection, 0, 2), "big")
    if nlen > 1024:
        raise RuntimeError("NDEF length exceeds the safe inspection limit")
    output = bytearray()
    offset = 2
    while len(output) < nlen:
        chunk_length = min(0xF0, nlen - len(output))
        output.extend(read_binary(connection, offset, chunk_length))
        offset += chunk_length
    return bytes(output)


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
    apdu = [0x90, 0xF5, 0x00, 0x00, 0x01, file_number, 0x00]
    return expect_ok(transmit(connection, apdu), "GetFileSettings")


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


def inspect_card() -> None:
    reader = find_picc_reader()
    connection = reader.createConnection()
    connection.connect()

    uid = expect_ok(
        transmit(connection, [0xFF, 0xCA, 0x00, 0x00, 0x00]),
        "UID read",
    )
    print(f"Reader: {reader}")
    print(f"UID: {hex_text(uid)}")
    print(f"Version data: {hex_text(get_version(connection))}")

    select_by_name(connection, NDEF_APPLICATION)
    try:
        settings = get_file_settings(connection)
        print(f"NDEF file settings: {hex_text(settings)}")
    except RuntimeError as error:
        print(f"NDEF file settings: unavailable ({error})")

    ndef = read_ndef(connection)
    print(f"NDEF bytes: {hex_text(ndef)}")
    print("INSPECTION COMPLETE — NO TAG DATA WAS CHANGED")


def safety_check() -> None:
    for cla_ins in READ_ONLY_COMMANDS:
        require_read_only(cla_ins)
    for ins in BLOCKED_INSTRUCTIONS:
        try:
            require_read_only([0x90, ins])
        except PermissionError:
            continue
        raise RuntimeError(f"Blocked instruction {ins:02X} was unexpectedly allowed")
    print("READ-ONLY INSPECTOR READY")
    print("Reader access: DISABLED")
    print("Tag writes: BLOCKED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--safety-check", action="store_true")
    mode.add_argument("--inspect", action="store_true")
    args = parser.parse_args()

    if args.inspect:
        inspect_card()
    else:
        safety_check()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

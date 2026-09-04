#!/usr/bin/env python3
"""Locked release candidate for controlled FUR NTAG 424 DNA provisioning."""

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntag424_execution_manifest import build_manifest
from ntag424_locked_transport import safety_check as transport_safety_check
from ntag424_provision import PROVISIONING_STEPS
from ntag424_auth_key_validate import (
    change_authenticated_key_apdu,
    change_other_key_apdu,
)
from ntag424_ev2_validate import protect_command
from ntag424_provision import EXPECTED_SETTINGS
from ntag424_live_preflight import FACTORY_KEY_0, authenticate_ev2_first_with_key
from ntag424_simulate_provision import verify_sun
from ntag424_recovery_journal import PersistentRecoveryJournal
from ntag424_write_validate import verify_protected_response

LIVE_EXECUTION_ENABLED = False
AUTHORISATION_PHRASE = "PROVISION FUR TAG PERMANENTLY"
# GetFileSettings returns: FileType, FileOption/AccessRights, FileSize,
# then the optional SDM settings. ChangeFileSettings does not include FileSize.
EXPECTED_LIVE_FILE_SETTINGS = (
    b"\x00"
    + EXPECTED_SETTINGS[:3]
    + bytes.fromhex("000100")
    + EXPECTED_SETTINGS[3:]
)


@dataclass
class LiveSession:
    ti: bytes
    enc_key: bytes
    mac_key: bytes
    command_counter: int = 0
    active: bool = True


def require_active_session(session: LiveSession) -> None:
    if not session.active:
        raise RuntimeError("Authenticated session is no longer active")


def replace_other_key_verified(
    connection,
    session: LiveSession,
    key_number: int,
    old_key: bytes,
    new_key: bytes,
    authority: str,
) -> None:
    if authority != AUTHORISATION_PHRASE:
        raise PermissionError("Permanent provisioning authority is missing")
    if key_number not in range(1, 5):
        raise ValueError("This stage is locked to keys 1 through 4")
    require_active_session(session)
    apdu = change_other_key_apdu(
        key_number, old_key, new_key, 1, session.command_counter,
        session.enc_key, session.mac_key, session.ti,
    )
    data, sw1, sw2 = connection.transmit(list(apdu))
    verify_protected_response(
        bytes(data) + bytes([sw1, sw2]), session.command_counter,
        session.ti, session.mac_key,
    )
    session.command_counter += 1


def write_ndef_verified(connection, session, ndef_file, authority):
    if authority != AUTHORISATION_PHRASE:
        raise PermissionError("Permanent provisioning authority is missing")
    if len(ndef_file) != 107:
        raise ValueError("FUR NDEF payload must contain exactly 107 bytes")
    require_active_session(session)
    # ISOUpdateBinary operates on the currently selected ISO file. Select the
    # NFC Forum NDEF application and its NDEF file explicitly before writing.
    commands = (
        ("NDEF application select", bytes.fromhex("00A4040C07D2760000850101")),
        ("NDEF file select", bytes.fromhex("00A4000C02E104")),
        (
            "NDEF write",
            bytes([0x00, 0xD6, 0x00, 0x00, len(ndef_file)]) + ndef_file,
        ),
    )
    for operation, apdu in commands:
        data, sw1, sw2 = connection.transmit(list(apdu))
        if data or (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError(
                f"ISO {operation} failed: {sw1:02X}{sw2:02X}"
            )


def verify_ndef_readback(expected, received):
    if len(expected) != 107 or received != expected:
        raise RuntimeError("NDEF read-back verification failed")


def apply_sdm_settings_verified(connection, session, authority):
    if authority != AUTHORISATION_PHRASE:
        raise PermissionError("Permanent provisioning authority is missing")
    require_active_session(session)
    apdu = protect_command(
        0x5F, b"\x02", EXPECTED_SETTINGS, session.enc_key,
        session.mac_key, session.ti, session.command_counter,
    ).apdu
    data, sw1, sw2 = connection.transmit(list(apdu))
    verify_protected_response(
        bytes(data) + bytes([sw1, sw2]), session.command_counter,
        session.ti, session.mac_key,
    )
    session.command_counter += 1


def verify_sdm_settings_readback(received):
    if received != EXPECTED_LIVE_FILE_SETTINGS:
        raise RuntimeError("SDM settings read-back verification failed")


def replace_administration_key_last(
    connection,
    session: LiveSession,
    new_key: bytes,
    authority: str,
    prior_stages_verified: bool,
) -> None:
    if authority != AUTHORISATION_PHRASE:
        raise PermissionError("Permanent provisioning authority is missing")
    if not prior_stages_verified:
        raise RuntimeError("Administration key 0 is locked until all prior stages verify")
    require_active_session(session)
    apdu = change_authenticated_key_apdu(
        0, new_key, 1, session.command_counter,
        session.enc_key, session.mac_key, session.ti,
    )
    data, sw1, sw2 = connection.transmit(list(apdu))
    if data or (sw1, sw2) != (0x91, 0x00):
        raise RuntimeError("Administration key 0 replacement was not confirmed")
    session.active = False


def verify_production_completion(
    connection,
    replaced_session: LiveSession,
    production_admin_key: bytes,
    production_sdm_key: bytes,
    uid_hex: str,
    counter_hex: str,
    mac_hex: str,
) -> LiveSession:
    if replaced_session.active:
        raise RuntimeError("Production verification requires a completed key-0 change")
    authenticated = authenticate_ev2_first_with_key(
        connection, 0, production_admin_key
    )
    verify_sun(uid_hex, counter_hex, mac_hex, production_sdm_key)
    return LiveSession(
        authenticated.ti,
        authenticated.session_enc_key,
        authenticated.session_mac_key,
    )


class LiveProvisioningCoordinator:
    """Record each verified live stage without placing key material in the journal."""

    def __init__(self, journal: PersistentRecoveryJournal, session: LiveSession):
        self.journal = journal
        self.session = session

    def record_preflight(self, evidence: bytes) -> None:
        self.journal.record("preflight_verified", True, evidence)

    def replace_key(self, connection, key_number, old_key, new_key, authority):
        checkpoint = f"key_{key_number}_changed_verified"
        self.journal.begin(checkpoint)
        replace_other_key_verified(
            connection, self.session, key_number, old_key, new_key, authority
        )
        verified = authenticate_ev2_first_with_key(connection, key_number, new_key)
        restored = authenticate_ev2_first_with_key(connection, 0, FACTORY_KEY_0)
        self.session = LiveSession(
            restored.ti, restored.session_enc_key, restored.session_mac_key
        )
        self.journal.confirm(
            checkpoint,
            bytes([key_number]) + verified.ti,
        )

    def write_and_verify_ndef(
        self, connection, ndef_file, readback, authority
    ) -> None:
        self.journal.begin("ndef_readback_verified")
        write_ndef_verified(connection, self.session, ndef_file, authority)
        if callable(readback):
            readback = readback()
        verify_ndef_readback(ndef_file, readback)
        self.journal.confirm("ndef_readback_verified", readback)

    def apply_and_verify_sdm(self, connection, readback, authority) -> None:
        self.journal.begin("sdm_settings_readback_verified")
        apply_sdm_settings_verified(connection, self.session, authority)
        if callable(readback):
            readback = readback()
        verify_sdm_settings_readback(readback)
        self.journal.confirm("sdm_settings_readback_verified", readback)

    def replace_key_zero(self, connection, new_key, authority) -> None:
        self.journal.begin("key_0_changed")
        replace_administration_key_last(
            connection, self.session, new_key, authority,
            prior_stages_verified=(
                len(self.journal.state["checkpoints"]) == 7
            ),
        )
        self.journal.confirm("key_0_changed", b"status-9100")

    def complete(
        self, connection, admin_key, sdm_key, uid, counter, mac
    ) -> LiveSession:
        self.journal.begin("production_auth_and_sun_verified")
        production_session = verify_production_completion(
            connection, self.session, admin_key, sdm_key, uid, counter, mac
        )
        self.journal.confirm(
            "production_auth_and_sun_verified",
            bytes.fromhex(uid + counter + mac),
        )
        return production_session


def release_candidate_check(tag_id: str, expected_uid: str) -> dict:
    manifest = build_manifest(tag_id, expected_uid)
    transport_safety_check()
    if LIVE_EXECUTION_ENABLED:
        raise RuntimeError("Safety build must not enable live execution")
    if PROVISIONING_STEPS[-2].action != "Replace administration key 0 last":
        raise RuntimeError("Administration key recovery boundary changed")
    if manifest["recovery_boundary"] != "key-0-last":
        raise RuntimeError("Manifest recovery boundary changed")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--safety-check", action="store_true")
    parser.add_argument("--tag-id", default="FUR-000001")
    parser.add_argument("--expected-uid", required=True)
    args = parser.parse_args()
    try:
        manifest = release_candidate_check(args.tag_id, args.expected_uid)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"LIVE PROVISIONER CHECK FAILED — {error}")
        return 1
    print("FUR NTAG 424 DNA — LIVE PROVISIONER RELEASE CANDIDATE")
    print("Reader access: DISABLED")
    print("Persistent tag writes: BLOCKED")
    print(f"Manifest SHA-256: {manifest['manifest_sha256']}")
    print("Identity, keys, payload, SDM profile and recovery order: VERIFIED")
    print("LIVE PROVISIONER SAFETY BUILD PASSED — EXECUTION IS NOT ENABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

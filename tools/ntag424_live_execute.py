#!/usr/bin/env python3
"""Hard-locked physical wrapper for one FUR NTAG 424 DNA provisioning run."""

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntag424_dry_run import build_plan
from ntag424_execution_manifest import build_manifest
from ntag424_inspect import read_ndef
from ntag424_live_preflight import (
    EXPECTED_FACTORY_FILE_SETTINGS,
    FACTORY_KEY_0,
    authenticate_ev2_first_with_key,
    find_picc_reader,
    get_file_settings,
    get_version,
    read_uid,
    select_ndef_application,
    validate_version,
)
from ntag424_live_provision import (
    AUTHORISATION_PHRASE,
    EXPECTED_LIVE_FILE_SETTINGS,
    LiveProvisioningCoordinator,
    LiveSession,
)
from ntag424_recovery_journal import PersistentRecoveryJournal
from ntag424_simulate_provision import load_production_keys

LIVE_EXECUTION_ENABLED = False
SUN_PATTERN = re.compile(
    rb"[?&]uid=([0-9A-Fa-f]{14})&ctr=([0-9A-Fa-f]{6})&cmac=([0-9A-Fa-f]{16})"
)


def require_live_authority(authority: str) -> None:
    if not LIVE_EXECUTION_ENABLED:
        raise PermissionError("Live physical execution is hard-locked")
    if authority != AUTHORISATION_PHRASE:
        raise PermissionError("Permanent provisioning authority is missing")


def extract_sun_fields(ndef: bytes):
    match = SUN_PATTERN.search(ndef)
    if match is None:
        raise RuntimeError("Dynamic SUN fields were not found in NDEF read-back")
    return tuple(value.decode("ascii").upper() for value in match.groups())


def read_full_ndef_file(connection):
    message = read_ndef(connection)
    return len(message).to_bytes(2, "big") + message


def execute_live(tag_id, expected_uid, journal_path, authority):
    # This must remain the first operation: no keychain or reader access before it.
    require_live_authority(authority)
    manifest = build_manifest(tag_id, expected_uid)
    keys = load_production_keys()
    plan = build_plan(tag_id)
    path = Path(journal_path)
    if path.exists():
        existing = PersistentRecoveryJournal.load(
            path, tag_id, expected_uid, manifest["manifest_sha256"]
        )
        raise RuntimeError(f"Existing recovery journal: {existing.recovery_action}")

    reader = find_picc_reader()
    connection = reader.createConnection()
    connection.connect()
    uid = read_uid(connection)
    if uid.hex().upper() != expected_uid.upper():
        raise RuntimeError("Live execution UID mismatch")
    select_ndef_application(connection)
    version = get_version(connection)
    validate_version(version, uid)
    settings = get_file_settings(connection)
    if settings != EXPECTED_FACTORY_FILE_SETTINGS:
        raise RuntimeError("Live execution requires factory NDEF settings")
    authenticated = authenticate_ev2_first_with_key(connection, 0, FACTORY_KEY_0)
    journal = PersistentRecoveryJournal.create(
        path, tag_id, expected_uid, manifest["manifest_sha256"]
    )
    coordinator = LiveProvisioningCoordinator(
        journal,
        LiveSession(
            authenticated.ti,
            authenticated.session_enc_key,
            authenticated.session_mac_key,
        ),
    )
    coordinator.record_preflight(uid + version + settings)

    for key_number in range(1, 5):
        coordinator.replace_key(
            connection, key_number, FACTORY_KEY_0, keys[key_number], authority
        )

    coordinator.write_and_verify_ndef(
        connection, plan.ndef_file, lambda: read_full_ndef_file(connection), authority
    )
    select_ndef_application(connection)
    restored = authenticate_ev2_first_with_key(connection, 0, FACTORY_KEY_0)
    coordinator.session = LiveSession(
        restored.ti, restored.session_enc_key, restored.session_mac_key
    )
    coordinator.apply_and_verify_sdm(
        connection, lambda: get_file_settings(connection), authority
    )
    coordinator.replace_key_zero(connection, keys[0], authority)
    dynamic_ndef = read_full_ndef_file(connection)
    sun_uid, counter, mac = extract_sun_fields(dynamic_ndef)
    coordinator.complete(connection, keys[0], keys[1], sun_uid, counter, mac)
    return journal


def safety_check():
    if LIVE_EXECUTION_ENABLED:
        raise RuntimeError("Safety build unexpectedly enables live execution")
    try:
        execute_live(
            "FUR-000001", "044517DA291D90", "/invalid/journal", "NO"
        )
    except PermissionError as error:
        if "hard-locked" not in str(error):
            raise
    else:
        raise RuntimeError("Execution lock was bypassed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--safety-check", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--tag-id", default="FUR-000001")
    parser.add_argument("--expected-uid", required=True)
    parser.add_argument(
        "--journal",
        default=str(Path.home() / "Documents" / "FUR-NTAG-Live-Recovery.json"),
    )
    parser.add_argument("--authority", default="")
    args = parser.parse_args()
    try:
        if args.execute:
            journal = execute_live(
                args.tag_id, args.expected_uid, args.journal, args.authority
            )
            print(f"LIVE PROVISIONING: {journal.recovery_action}")
        else:
            safety_check()
            print("LIVE EXECUTION WRAPPER READY — PHYSICAL EXECUTION IS HARD-LOCKED")
            print("Reader access: DISABLED")
            print("Keychain access: DISABLED")
            print("Persistent tag writes: BLOCKED")
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        print(f"LIVE EXECUTION STOPPED — {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

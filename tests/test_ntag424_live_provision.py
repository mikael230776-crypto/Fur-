import importlib.util
import pathlib
import tempfile
import unittest
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_live_provision.py"
SPEC = importlib.util.spec_from_file_location("ntag424_live_provision", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LiveProvisionReleaseCandidateTests(unittest.TestCase):
    @staticmethod
    def response_connection(session):
        class Connection:
            def transmit(self, apdu):
                message = b"\x00" + (session.command_counter + 1).to_bytes(2, "little") + session.ti
                full = CMAC.new(session.mac_key, ciphermod=AES)
                full.update(message)
                return list(full.digest()[1::2]), 0x91, 0x00
        return Connection()
    def test_execution_is_hard_locked(self):
        self.assertFalse(MODULE.LIVE_EXECUTION_ENABLED)

    def test_no_reader_discovery_is_present_while_execution_is_locked(self):
        source = PATH.read_text()
        self.assertNotRegex(source, r"(?m)^\s*(from|import)\s+smartcard")
        self.assertFalse(MODULE.LIVE_EXECUTION_ENABLED)

    def test_release_check_composes_manifest_and_transport_gates(self):
        original_manifest = MODULE.build_manifest
        original_transport = MODULE.transport_safety_check
        MODULE.build_manifest = lambda *_: {"recovery_boundary": "key-0-last", "manifest_sha256": "a" * 64}
        MODULE.transport_safety_check = lambda: None
        try:
            result = MODULE.release_candidate_check("FUR-000001", "04112233445566")
            self.assertEqual(result["manifest_sha256"], "a" * 64)
        finally:
            MODULE.build_manifest = original_manifest
            MODULE.transport_safety_check = original_transport

    def test_key_replacement_requires_authority_and_verified_response(self):
        session = MODULE.LiveSession(bytes.fromhex("7614281A"), bytes(16), bytes.fromhex("5529860B2FC5FB6154B7F28361D30BF9"))
        class Connection:
            def transmit(self, apdu):
                message = bytes.fromhex("00") + bytes.fromhex("0100") + session.ti
                full = CMAC.new(session.mac_key, ciphermod=AES)
                full.update(message)
                return list(full.digest()[1::2]), 0x91, 0x00
        with self.assertRaises(PermissionError):
            MODULE.replace_other_key_verified(Connection(), session, 1, bytes(16), bytes([1])*16, "NO")
        MODULE.replace_other_key_verified(Connection(), session, 1, bytes(16), bytes([1])*16, MODULE.AUTHORISATION_PHRASE)
        self.assertEqual(session.command_counter, 1)

    def test_key_zero_cannot_be_changed_in_early_stage(self):
        session = MODULE.LiveSession(bytes(4), bytes(16), bytes(16))
        with self.assertRaisesRegex(ValueError, "1 through 4"):
            MODULE.replace_other_key_verified(None, session, 0, bytes(16), bytes([1])*16, MODULE.AUTHORISATION_PHRASE)

    def test_ndef_write_requires_exact_payload_and_verified_response(self):
        session = MODULE.LiveSession(bytes.fromhex("7614281A"), bytes(16), bytes.fromhex("5529860B2FC5FB6154B7F28361D30BF9"))
        with self.assertRaises(ValueError):
            MODULE.write_ndef_verified(None, session, b"short", MODULE.AUTHORISATION_PHRASE)
        payload = bytes(107)
        class Connection:
            def __init__(self):
                self.apdus = []

            def transmit(self, apdu):
                self.apdus.append(bytes(apdu))
                return [], 0x90, 0x00
        connection = Connection()
        MODULE.write_ndef_verified(connection, session, payload, MODULE.AUTHORISATION_PHRASE)
        self.assertEqual(
            connection.apdus[:2],
            [
                bytes.fromhex("00A4040C07D2760000850101"),
                bytes.fromhex("00A4000C02E104"),
            ],
        )
        self.assertEqual(connection.apdus[2][:5], bytes.fromhex("00D600006B"))
        self.assertEqual(connection.apdus[2][5:], payload)
        self.assertEqual(session.command_counter, 0)

    def test_ndef_plain_write_requires_iso_success_status(self):
        session = MODULE.LiveSession(bytes(4), bytes(16), bytes(16))
        class Connection:
            def transmit(self, apdu):
                return [], 0x91, 0xAE
        with self.assertRaisesRegex(RuntimeError, "91AE"):
            MODULE.write_ndef_verified(
                Connection(), session, bytes(107), MODULE.AUTHORISATION_PHRASE
            )

    def test_ndef_write_stops_if_iso_file_selection_fails(self):
        session = MODULE.LiveSession(bytes(4), bytes(16), bytes(16))

        class Connection:
            def __init__(self):
                self.calls = 0

            def transmit(self, apdu):
                self.calls += 1
                if self.calls == 2:
                    return [], 0x69, 0x85
                return [], 0x90, 0x00

        connection = Connection()
        with self.assertRaisesRegex(RuntimeError, "NDEF file select failed: 6985"):
            MODULE.write_ndef_verified(
                connection, session, bytes(107), MODULE.AUTHORISATION_PHRASE
            )
        self.assertEqual(connection.calls, 2)

    def test_ndef_readback_must_match_byte_for_byte(self):
        payload = bytes(range(107))
        MODULE.verify_ndef_readback(payload, payload)
        with self.assertRaisesRegex(RuntimeError, "read-back"):
            MODULE.verify_ndef_readback(payload, payload[:-1] + b"x")

    def test_sdm_settings_require_authority_and_verified_response(self):
        session = MODULE.LiveSession(bytes.fromhex("7614281A"), bytes(16), bytes.fromhex("5529860B2FC5FB6154B7F28361D30BF9"))
        with self.assertRaises(PermissionError):
            MODULE.apply_sdm_settings_verified(None, session, "NO")
        MODULE.apply_sdm_settings_verified(self.response_connection(session), session, MODULE.AUTHORISATION_PHRASE)
        self.assertEqual(session.command_counter, 1)

    def test_sdm_settings_readback_is_exact(self):
        MODULE.verify_sdm_settings_readback(MODULE.EXPECTED_LIVE_FILE_SETTINGS)
        altered = bytearray(MODULE.EXPECTED_LIVE_FILE_SETTINGS)
        altered[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, "SDM settings"):
            MODULE.verify_sdm_settings_readback(bytes(altered))

    def test_administration_key_is_changed_only_after_prior_stages(self):
        session = MODULE.LiveSession(bytes(4), bytes(16), bytes(16), 7)

        class Connection:
            def transmit(self, apdu):
                return [], 0x91, 0x00

        with self.assertRaises(PermissionError):
            MODULE.replace_administration_key_last(
                Connection(), session, bytes([9]) * 16, "NO", True
            )
        with self.assertRaisesRegex(RuntimeError, "prior stages"):
            MODULE.replace_administration_key_last(
                Connection(), session, bytes([9]) * 16,
                MODULE.AUTHORISATION_PHRASE, False,
            )
        MODULE.replace_administration_key_last(
            Connection(), session, bytes([9]) * 16,
            MODULE.AUTHORISATION_PHRASE, True,
        )
        self.assertFalse(session.active)

    def test_key_zero_failure_preserves_active_session(self):
        session = MODULE.LiveSession(bytes(4), bytes(16), bytes(16))

        class Connection:
            def transmit(self, apdu):
                return [], 0x91, 0xAE

        with self.assertRaisesRegex(RuntimeError, "not confirmed"):
            MODULE.replace_administration_key_last(
                Connection(), session, bytes([9]) * 16,
                MODULE.AUTHORISATION_PHRASE, True,
            )
        self.assertTrue(session.active)

    def test_invalidated_session_blocks_further_mutation(self):
        session = MODULE.LiveSession(bytes(4), bytes(16), bytes(16), active=False)
        with self.assertRaisesRegex(RuntimeError, "no longer active"):
            MODULE.write_ndef_verified(
                None, session, bytes(107), MODULE.AUTHORISATION_PHRASE
            )

    def test_completion_requires_key_zero_change_then_auth_and_sun(self):
        replaced = MODULE.LiveSession(bytes(4), bytes(16), bytes(16), active=False)
        original_auth = MODULE.authenticate_ev2_first_with_key
        original_sun = MODULE.verify_sun
        calls = []

        class Authenticated:
            ti = bytes.fromhex("01020304")
            session_enc_key = bytes([5]) * 16
            session_mac_key = bytes([6]) * 16

        MODULE.authenticate_ev2_first_with_key = (
            lambda connection, key_number, key: calls.append(
                ("auth", key_number, key)
            ) or Authenticated()
        )
        MODULE.verify_sun = (
            lambda uid, counter, mac, key: calls.append(
                ("sun", uid, counter, mac, key)
            )
        )
        try:
            completed = MODULE.verify_production_completion(
                object(), replaced, bytes([1]) * 16, bytes([2]) * 16,
                "044517DA291D90", "010000", "0011223344556677",
            )
        finally:
            MODULE.authenticate_ev2_first_with_key = original_auth
            MODULE.verify_sun = original_sun

        self.assertEqual([call[0] for call in calls], ["auth", "sun"])
        self.assertTrue(completed.active)
        self.assertEqual(completed.command_counter, 0)

    def test_completion_rejects_active_old_session(self):
        with self.assertRaisesRegex(RuntimeError, "key-0 change"):
            MODULE.verify_production_completion(
                None, MODULE.LiveSession(bytes(4), bytes(16), bytes(16)),
                bytes([1]) * 16, bytes([2]) * 16,
                "044517DA291D90", "010000", "0011223344556677",
            )

    def test_failed_sun_never_returns_completed_session(self):
        replaced = MODULE.LiveSession(bytes(4), bytes(16), bytes(16), active=False)
        original_auth = MODULE.authenticate_ev2_first_with_key
        MODULE.authenticate_ev2_first_with_key = lambda *_: type(
            "Authenticated", (), {
                "ti": bytes(4),
                "session_enc_key": bytes(16),
                "session_mac_key": bytes(16),
            }
        )()
        try:
            with self.assertRaisesRegex(RuntimeError, "SUN"):
                MODULE.verify_production_completion(
                    object(), replaced, bytes([1]) * 16, bytes([2]) * 16,
                    "044517DA291D90", "010000", "0011223344556677",
                )
        finally:
            MODULE.authenticate_ev2_first_with_key = original_auth

    def test_every_physical_write_boundary_persists_pending_recovery(self):
        boundaries = (
            "key_1_changed_verified", "key_2_changed_verified",
            "key_3_changed_verified", "key_4_changed_verified",
            "ndef_readback_verified", "sdm_settings_readback_verified",
            "key_0_changed",
        )
        ordered_prerequisites = (
            "preflight_verified",
            "key_1_changed_verified", "key_2_changed_verified",
            "key_3_changed_verified", "key_4_changed_verified",
            "ndef_readback_verified", "sdm_settings_readback_verified",
        )
        originals = {
            "key": MODULE.replace_other_key_verified,
            "ndef": MODULE.write_ndef_verified,
            "sdm": MODULE.apply_sdm_settings_verified,
            "key0": MODULE.replace_administration_key_last,
        }

        def interrupted(*args, **kwargs):
            raise RuntimeError("SIMULATED POWER LOSS")

        try:
            for target_index, checkpoint in enumerate(boundaries, start=1):
                with self.subTest(checkpoint=checkpoint), tempfile.TemporaryDirectory() as tmp:
                    path = pathlib.Path(tmp) / "journal.json"
                    journal = MODULE.PersistentRecoveryJournal.create(
                        path, "FUR-000001", "044517DA291D90", "a" * 64
                    )
                    for prior in ordered_prerequisites[:target_index]:
                        journal.record(prior, True, prior.encode())
                    coordinator = MODULE.LiveProvisioningCoordinator(
                        journal, MODULE.LiveSession(bytes(4), bytes(16), bytes(16))
                    )
                    if checkpoint.startswith("key_") and checkpoint != "key_0_changed":
                        MODULE.replace_other_key_verified = interrupted
                        operation = lambda: coordinator.replace_key(
                            None, target_index, bytes(16), bytes([target_index]) * 16,
                            MODULE.AUTHORISATION_PHRASE,
                        )
                    elif checkpoint == "ndef_readback_verified":
                        MODULE.write_ndef_verified = interrupted
                        operation = lambda: coordinator.write_and_verify_ndef(
                            None, bytes(107), bytes(107), MODULE.AUTHORISATION_PHRASE
                        )
                    elif checkpoint == "sdm_settings_readback_verified":
                        MODULE.apply_sdm_settings_verified = interrupted
                        operation = lambda: coordinator.apply_and_verify_sdm(
                            None, MODULE.EXPECTED_LIVE_FILE_SETTINGS,
                            MODULE.AUTHORISATION_PHRASE,
                        )
                    else:
                        MODULE.replace_administration_key_last = interrupted
                        operation = lambda: coordinator.replace_key_zero(
                            None, bytes([9]) * 16, MODULE.AUTHORISATION_PHRASE
                        )
                    with self.assertRaisesRegex(RuntimeError, "POWER LOSS"):
                        operation()
                    loaded = MODULE.PersistentRecoveryJournal.load(
                        path, "FUR-000001", "044517DA291D90", "a" * 64
                    )
                    self.assertEqual(loaded.state["pending"], checkpoint)
                    MODULE.replace_other_key_verified = originals["key"]
                    MODULE.write_ndef_verified = originals["ndef"]
                    MODULE.apply_sdm_settings_verified = originals["sdm"]
                    MODULE.replace_administration_key_last = originals["key0"]
        finally:
            MODULE.replace_other_key_verified = originals["key"]
            MODULE.write_ndef_verified = originals["ndef"]
            MODULE.apply_sdm_settings_verified = originals["sdm"]
            MODULE.replace_administration_key_last = originals["key0"]

if __name__ == "__main__":
    unittest.main()

import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_live_execute.py"
SPEC = importlib.util.spec_from_file_location("ntag424_live_execute", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LiveExecutionWrapperTests(unittest.TestCase):
    def test_live_execution_is_hard_locked(self):
        with self.assertRaisesRegex(PermissionError, "hard-locked"):
            MODULE.execute_live(
                "FUR-000001", "044517DA291D90", "/invalid", "NO"
            )

    def test_lock_precedes_keychain_and_reader_access(self):
        original_keys = MODULE.load_production_keys
        original_reader = MODULE.find_picc_reader
        MODULE.load_production_keys = lambda: self.fail("keychain was accessed")
        MODULE.find_picc_reader = lambda: self.fail("reader was accessed")
        try:
            MODULE.safety_check()
        finally:
            MODULE.load_production_keys = original_keys
            MODULE.find_picc_reader = original_reader

    def test_sun_fields_are_extracted_strictly(self):
        fields = MODULE.extract_sun_fields(
            b"x?tagId=FUR-000001&uid=044517DA291D90&ctr=010000&cmac=0011223344556677"
        )
        self.assertEqual(
            fields, ("044517DA291D90", "010000", "0011223344556677")
        )
        with self.assertRaisesRegex(RuntimeError, "SUN fields"):
            MODULE.extract_sun_fields(b"uid=bad")

    def test_full_ndef_readback_restores_two_byte_length(self):
        original = MODULE.read_ndef
        MODULE.read_ndef = lambda connection: b"abc"
        try:
            self.assertEqual(MODULE.read_full_ndef_file(None), b"\x00\x03abc")
        finally:
            MODULE.read_ndef = original

    def test_generic_key_verification_restores_factory_session(self):
        journal = type("Journal", (), {
            "begin": lambda self, checkpoint: None,
            "confirm": lambda self, checkpoint, evidence: setattr(self, "evidence", evidence),
        })()
        coordinator = MODULE.LiveProvisioningCoordinator(
            journal, MODULE.LiveSession(bytes(4), bytes(16), bytes(16))
        )
        provision_module = __import__("ntag424_live_provision")
        original_low = provision_module.replace_other_key_verified
        original_auth = provision_module.authenticate_ev2_first_with_key
        calls = []
        provision_module.replace_other_key_verified = lambda *args: calls.append("change")
        provision_module.authenticate_ev2_first_with_key = lambda connection, number, key: type(
            "Session", (), {
                "ti": bytes([number]) * 4,
                "session_enc_key": bytes([number]) * 16,
                "session_mac_key": bytes([number]) * 16,
            }
        )()
        try:
            coordinator.replace_key(None, 1, bytes(16), bytes([1]) * 16, MODULE.AUTHORISATION_PHRASE)
        finally:
            provision_module.replace_other_key_verified = original_low
            provision_module.authenticate_ev2_first_with_key = original_auth
        self.assertEqual(calls, ["change"])
        self.assertEqual(coordinator.session.ti, bytes(4))
        self.assertEqual(journal.evidence, b"\x01" * 5)

    def test_recovery_accepts_only_exact_interruption_states(self):
        through_keys = [
            "preflight_verified", "key_1_changed_verified",
            "key_2_changed_verified", "key_3_changed_verified",
            "key_4_changed_verified",
        ]
        self.assertEqual(
            MODULE.classify_recovery_state(
                through_keys, "ndef_readback_verified"
            ),
            "ndef",
        )
        self.assertEqual(
            MODULE.classify_recovery_state(
                through_keys + ["ndef_readback_verified"],
                "sdm_settings_readback_verified",
            ),
            "sdm_readback",
        )
        with self.assertRaisesRegex(RuntimeError, "Unsupported recovery state"):
            MODULE.classify_recovery_state(
                through_keys, "sdm_settings_readback_verified"
            )

    def test_recovery_rejects_other_checkpoint_states(self):
        original_manifest = MODULE.build_manifest
        original_keys = MODULE.load_production_keys
        original_load = MODULE.PersistentRecoveryJournal.load
        MODULE.build_manifest = lambda *_: {"manifest_sha256": "a" * 64}
        MODULE.load_production_keys = lambda: [bytes(16)] * 5
        journal = type("Journal", (), {
            "state": {"checkpoints": [], "pending": None},
            "recovery_action": "RESUME AT preflight_verified",
        })()
        MODULE.PersistentRecoveryJournal.load = lambda *_: journal
        release = MODULE.ExecutionRelease("044517DA291D90", "a" * 64)
        try:
            with self.assertRaisesRegex(RuntimeError, "Unsupported recovery state"):
                MODULE.recover_live(
                    "FUR-000001", "044517DA291D90", "/journal",
                    MODULE.AUTHORISATION_PHRASE, release,
                )
        finally:
            MODULE.build_manifest = original_manifest
            MODULE.load_production_keys = original_keys
            MODULE.PersistentRecoveryJournal.load = original_load


if __name__ == "__main__":
    unittest.main()

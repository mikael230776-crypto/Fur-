import importlib.util
import json
import pathlib
import tempfile
import unittest

PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_recovery_journal.py"
SPEC = importlib.util.spec_from_file_location("ntag424_recovery_journal", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PersistentRecoveryJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temporary.name) / "recovery.json"
        self.manifest = "a" * 64

    def tearDown(self):
        self.temporary.cleanup()

    def create(self):
        return MODULE.PersistentRecoveryJournal.create(
            self.path, "FUR-000001", "044517DA291D90", self.manifest
        )

    def test_journal_is_persistent_bound_and_contains_no_keys(self):
        journal = self.create()
        journal.record("preflight_verified", True, b"verified preflight")
        loaded = MODULE.PersistentRecoveryJournal.load(
            self.path, "FUR-000001", "044517DA291D90", self.manifest
        )
        self.assertIn("key_1_changed_verified", loaded.recovery_action)
        self.assertNotIn("verified preflight", self.path.read_text())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_wrong_uid_or_manifest_fails_closed(self):
        self.create()
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            MODULE.PersistentRecoveryJournal.load(
                self.path, "FUR-000001", "044917DA291D90", self.manifest
            )
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            MODULE.PersistentRecoveryJournal.load(
                self.path, "FUR-000001", "044517DA291D90", "b" * 64
            )

    def test_only_verified_ordered_checkpoints_are_recorded(self):
        journal = self.create()
        with self.assertRaisesRegex(RuntimeError, "Unverified"):
            journal.record("preflight_verified", False, b"evidence")
        with self.assertRaisesRegex(RuntimeError, "skipped"):
            journal.record("ndef_readback_verified", True, b"evidence")
        self.assertEqual(journal.state["checkpoints"], [])

    def test_interruption_after_begin_requires_inspection(self):
        journal = self.create()
        journal.begin("preflight_verified")
        loaded = MODULE.PersistentRecoveryJournal.load(
            self.path, "FUR-000001", "044517DA291D90", self.manifest
        )
        self.assertEqual(
            loaded.recovery_action,
            "INSPECT TAG STATE BEFORE RECOVERING preflight_verified",
        )
        with self.assertRaisesRegex(RuntimeError, "already pending"):
            loaded.begin("preflight_verified")

    def test_key_zero_boundary_selects_production_recovery(self):
        journal = self.create()
        for checkpoint in MODULE.CHECKPOINTS[:8]:
            journal.record(checkpoint, True, checkpoint.encode())
        self.assertEqual(
            journal.recovery_action,
            "RE-AUTHENTICATE WITH PRODUCTION KEY 0 AND VERIFY SUN",
        )

    def test_complete_journal_cannot_accept_extra_checkpoint(self):
        journal = self.create()
        for checkpoint in MODULE.CHECKPOINTS:
            journal.record(checkpoint, True, checkpoint.encode())
        self.assertEqual(journal.recovery_action, "COMPLETE")
        with self.assertRaisesRegex(RuntimeError, "skipped"):
            journal.record("extra", True, b"evidence")

    def test_tampered_checkpoint_order_is_rejected_on_load(self):
        journal = self.create()
        journal.record("preflight_verified", True, b"evidence")
        state = json.loads(self.path.read_text())
        state["checkpoints"][0]["name"] = "key_0_changed"
        self.path.write_text(json.dumps(state))
        with self.assertRaisesRegex(RuntimeError, "order"):
            MODULE.PersistentRecoveryJournal.load(
                self.path, "FUR-000001", "044517DA291D90", self.manifest
            )


if __name__ == "__main__":
    unittest.main()

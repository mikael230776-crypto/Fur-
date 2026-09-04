import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_execution_manifest.py"
SPEC = importlib.util.spec_from_file_location("ntag424_execution_manifest", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExecutionManifestTests(unittest.TestCase):
    def setUp(self):
        self.original = MODULE.validate_production_keys
        MODULE.validate_production_keys = lambda: None

    def tearDown(self):
        MODULE.validate_production_keys = self.original

    def test_manifest_locks_identity_payload_profile_and_order(self):
        manifest = MODULE.build_manifest("FUR-000001", "04112233445566")
        self.assertEqual(manifest["ndef_length"], 107)
        self.assertEqual(manifest["change_file_settings"], MODULE.EXPECTED_SETTINGS.hex().upper())
        self.assertEqual(manifest["operation_order"], list(MODULE.ORDER))
        self.assertEqual(manifest["recovery_boundary"], "key-0-last")
        self.assertEqual(len(manifest["manifest_sha256"]), 64)

    def test_manifest_is_deterministic(self):
        first = MODULE.build_manifest("FUR-000001", "04112233445566")
        second = MODULE.build_manifest("FUR-000001", "04112233445566")
        self.assertEqual(first, second)

    def test_invalid_uid_fails_closed(self):
        with self.assertRaises(ValueError):
            MODULE.build_manifest("FUR-000001", "BAD")

    def test_source_has_no_reader_or_transport(self):
        source = MODULE_PATH.read_text()
        self.assertNotRegex(source, r"(?m)^\s*(from|import)\s+smartcard")
        self.assertNotIn(".transmit(", source)
        self.assertNotIn("createConnection", source)


if __name__ == "__main__":
    unittest.main()

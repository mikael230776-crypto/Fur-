import importlib.util
import pathlib
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_provision.py"
SPEC = importlib.util.spec_from_file_location("ntag424_provision", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProvisioningGateTests(unittest.TestCase):
    def test_uid_is_normalised(self):
        self.assertEqual(MODULE.normalise_uid("044917da291d90"), "044917DA291D90")

    def test_invalid_uid_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "14 hexadecimal"):
            MODULE.normalise_uid("1234")

    def test_five_unique_keys_pass(self):
        keys = [f"{number:032X}" for number in range(1, 6)]
        with patch.object(MODULE, "keychain_value", side_effect=keys):
            MODULE.validate_production_keys()

    def test_duplicate_key_is_rejected(self):
        keys = ["01" * 16, "02" * 16, "03" * 16, "04" * 16, "01" * 16]
        with patch.object(MODULE, "keychain_value", side_effect=keys):
            with self.assertRaisesRegex(ValueError, "distinct"):
                MODULE.validate_production_keys()

    def test_locked_profile_and_recovery_order(self):
        plan = MODULE.build_plan("FUR-000001")
        self.assertEqual(
            MODULE.build_change_file_settings_data(plan),
            MODULE.EXPECTED_SETTINGS,
        )
        MODULE.validate_step_order()
        actions = [step.action for step in MODULE.PROVISIONING_STEPS]
        self.assertEqual(actions[-2], "Replace administration key 0 last")
        for step in MODULE.PROVISIONING_STEPS[2:5]:
            self.assertEqual(step.recovery_checkpoint, "Factory key 0 retained")

    def test_source_has_no_reader_or_transmit_capability(self):
        source = MODULE_PATH.read_text()
        self.assertNotRegex(source, r"(?m)^\s*(from|import)\s+smartcard")
        self.assertNotIn(".transmit(", source)
        self.assertNotIn("connection.connect", source)


if __name__ == "__main__":
    unittest.main()

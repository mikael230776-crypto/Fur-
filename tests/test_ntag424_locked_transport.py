import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_locked_transport.py"
SPEC = importlib.util.spec_from_file_location("ntag424_locked_transport", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LockedTransportTests(unittest.TestCase):
    def test_all_mutations_are_blocked(self):
        transport = MODULE.LockedTransport()
        for instruction in MODULE.MUTATING_INS:
            with self.assertRaises(PermissionError):
                transport.transmit([0x90, instruction])

    def test_unknown_and_short_commands_fail_closed(self):
        transport = MODULE.LockedTransport()
        with self.assertRaises(ValueError):
            transport.transmit([0x90])
        with self.assertRaises(PermissionError):
            transport.transmit([0x90, 0x60])

    def test_official_vectors_and_order_pass(self):
        MODULE.safety_check()

    def test_settings_builder_is_protected_change_file_settings(self):
        apdu = MODULE.build_change_file_settings_apdu()
        self.assertEqual(apdu[:2], bytes.fromhex("905F"))
        self.assertEqual(apdu[-1], 0)
        self.assertNotIn(MODULE.EXPECTED_SETTINGS, apdu)


if __name__ == "__main__":
    unittest.main()

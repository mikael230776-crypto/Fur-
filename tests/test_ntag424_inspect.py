import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_inspect.py"
SPEC = importlib.util.spec_from_file_location("ntag424_inspect", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeConnection:
    def __init__(self):
        self.sent = []

    def transmit(self, apdu):
        self.sent.append(apdu)
        return [], 0x90, 0x00


class ReadOnlyInspectorTests(unittest.TestCase):
    def test_allows_only_declared_read_commands(self):
        for cla, ins in MODULE.READ_ONLY_COMMANDS:
            self.assertTrue(MODULE.require_read_only([cla, ins]))

    def test_blocks_tag_mutation_and_authentication_commands(self):
        for ins in MODULE.BLOCKED_INSTRUCTIONS:
            with self.assertRaises(PermissionError):
                MODULE.require_read_only([0x90, ins])

    def test_blocks_unknown_commands(self):
        with self.assertRaises(PermissionError):
            MODULE.require_read_only([0x90, 0x00])

    def test_transmit_checks_allowlist_before_reader(self):
        connection = FakeConnection()
        with self.assertRaises(PermissionError):
            MODULE.transmit(connection, [0x00, 0xD6, 0x00, 0x00, 0x01, 0x00])
        self.assertEqual(connection.sent, [])

    def test_select_and_read_commands_are_read_only(self):
        connection = FakeConnection()
        MODULE.select_by_name(connection, MODULE.NDEF_APPLICATION)
        MODULE.select_file(connection, MODULE.NDEF_FILE)
        MODULE.read_binary(connection, 0, 2)
        self.assertEqual([apdu[1] for apdu in connection.sent], [0xA4, 0xA4, 0xB0])


if __name__ == "__main__":
    unittest.main()

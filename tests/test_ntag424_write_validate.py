import importlib.util
import pathlib
import unittest

MODULE_PATH = (
    pathlib.Path(__file__).parents[1] / "tools" / "ntag424_write_validate.py"
)
SPEC = importlib.util.spec_from_file_location("ntag424_write_validate", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WriteResponseVectorTests(unittest.TestCase):
    def test_nxp_write_data_vector(self):
        apdu = MODULE.build_write_data_apdu(
            MODULE.NXP_WRITE_DATA,
            MODULE.SESSION_ENC_KEY,
            MODULE.SESSION_MAC_KEY,
            MODULE.TI,
            MODULE.COMMAND_COUNTER,
        )
        self.assertEqual(len(MODULE.NXP_WRITE_DATA), 128)
        self.assertEqual(apdu, MODULE.EXPECTED_WRITE_APDU)

    def test_nxp_response_mac_vector(self):
        expected = MODULE.response_mac(
            0x00,
            1,
            MODULE.TI,
            b"",
            MODULE.SESSION_MAC_KEY,
        )
        self.assertEqual(expected.hex().upper(), "FC222E5F7A542452")
        MODULE.verify_protected_response(
            MODULE.EXPECTED_RESPONSE,
            0,
            MODULE.TI,
            MODULE.SESSION_MAC_KEY,
        )

    def test_modified_response_is_rejected(self):
        modified = bytes([MODULE.EXPECTED_RESPONSE[0] ^ 1]) + MODULE.EXPECTED_RESPONSE[1:]
        with self.assertRaisesRegex(ValueError, "MAC"):
            MODULE.verify_protected_response(
                modified, 0, MODULE.TI, MODULE.SESSION_MAC_KEY
            )

    def test_journal_rejects_skipped_and_unverified_steps(self):
        with self.assertRaisesRegex(ValueError, "skipped"):
            MODULE.validate_journal(
                [MODULE.JournalEntry("keys_1_to_4_verified", True)]
            )
        with self.assertRaisesRegex(ValueError, "not verified"):
            MODULE.validate_journal(
                [MODULE.JournalEntry("preflight_verified", False)]
            )

    def test_journal_stops_safely_and_identifies_recovery(self):
        stopped = MODULE.validate_journal(
            [MODULE.JournalEntry("preflight_verified", True)]
        )
        self.assertEqual(
            stopped,
            "STOPPED SAFELY: next checkpoint is keys_1_to_4_verified",
        )
        recovery = MODULE.validate_journal(
            [MODULE.JournalEntry(name, True) for name in MODULE.CHECKPOINTS[:5]]
        )
        self.assertEqual(
            recovery,
            "RECOVERY REQUIRED: authenticate with production key 0",
        )

    def test_complete_journal(self):
        result = MODULE.validate_journal(
            [MODULE.JournalEntry(name, True) for name in MODULE.CHECKPOINTS]
        )
        self.assertEqual(result, "COMPLETE")

    def test_module_has_no_reader_or_transmit_capability(self):
        source = MODULE_PATH.read_text()
        self.assertNotRegex(source, r"(?m)^\s*(from|import)\s+smartcard")
        self.assertNotIn(".transmit(", source)
        self.assertNotIn("connection.connect", source)


if __name__ == "__main__":
    unittest.main()

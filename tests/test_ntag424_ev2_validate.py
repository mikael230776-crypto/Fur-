import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_ev2_validate.py"
SPEC = importlib.util.spec_from_file_location("ntag424_ev2_validate", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Ev2VectorTests(unittest.TestCase):
    def test_nxp_table_18_vector(self):
        self.assertTrue(MODULE.validate_nxp_table_18())

    def test_truncation_uses_odd_indexed_bytes(self):
        source = bytes(range(16))
        self.assertEqual(MODULE.truncate_mac(source), bytes([1, 3, 5, 7, 9, 11, 13, 15]))

    def test_padding_adds_full_block_for_aligned_input(self):
        padded = MODULE.iso7816_pad(bytes(16))
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[16], 0x80)
        self.assertEqual(padded[17:], bytes(15))

    def test_rejects_invalid_transaction_identifier(self):
        with self.assertRaises(ValueError):
            MODULE.command_iv(bytes(16), bytes(3), 0)

    def test_module_has_no_reader_dependency(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("smartcard", source)
        self.assertNotIn(".transmit(", source)


if __name__ == "__main__":
    unittest.main()

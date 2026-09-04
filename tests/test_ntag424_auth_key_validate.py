import importlib.util
import pathlib
import unittest

MODULE_PATH = (
    pathlib.Path(__file__).parents[1] / "tools" / "ntag424_auth_key_validate.py"
)
SPEC = importlib.util.spec_from_file_location("ntag424_auth_key_validate", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AuthenticationKeyVectorTests(unittest.TestCase):
    def test_nxp_authenticate_ev2_first_vector(self):
        result = MODULE.validate_authentication_vector()
        self.assertEqual(result.rnd_b, MODULE.AUTH_RNDB)
        self.assertEqual(result.part2, MODULE.AUTH_PART2_ENC)
        self.assertEqual(result.ti, MODULE.AUTH_TI)
        self.assertEqual(result.session_enc_key, MODULE.AUTH_ENC_KEY)
        self.assertEqual(result.session_mac_key, MODULE.AUTH_MAC_KEY)

    def test_session_vectors(self):
        sv_enc, sv_mac = MODULE.session_vectors(MODULE.AUTH_RNDA, MODULE.AUTH_RNDB)
        self.assertEqual(
            sv_enc.hex().upper(),
            "A55A0001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F",
        )
        self.assertEqual(
            sv_mac.hex().upper(),
            "5AA50001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F",
        )

    def test_nxp_different_key_change_vector(self):
        apdu = MODULE.change_other_key_apdu(
            2,
            MODULE.ZERO_KEY,
            MODULE.DIFFERENT_NEW_KEY,
            1,
            2,
            MODULE.CHANGE_ENC_KEY,
            MODULE.CHANGE_MAC_KEY,
            MODULE.CHANGE_TI,
        )
        self.assertEqual(MODULE.desfire_crc32(MODULE.DIFFERENT_NEW_KEY).hex().upper(), "789DFADC")
        self.assertEqual(apdu, MODULE.EXPECTED_DIFFERENT_APDU)

    def test_nxp_authenticated_key_change_vector(self):
        apdu = MODULE.change_authenticated_key_apdu(
            0,
            MODULE.SAME_NEW_KEY,
            1,
            3,
            MODULE.CHANGE_ENC_KEY,
            MODULE.CHANGE_MAC_KEY,
            MODULE.CHANGE_TI,
        )
        self.assertEqual(apdu, MODULE.EXPECTED_SAME_APDU)

    def test_rejects_invalid_key_lengths_and_numbers(self):
        with self.assertRaises(ValueError):
            MODULE.change_other_key_apdu(
                5, bytes(16), bytes(16), 1, 0,
                MODULE.CHANGE_ENC_KEY, MODULE.CHANGE_MAC_KEY, MODULE.CHANGE_TI,
            )
        with self.assertRaises(ValueError):
            MODULE.change_authenticated_key_apdu(
                0, bytes(15), 1, 0,
                MODULE.CHANGE_ENC_KEY, MODULE.CHANGE_MAC_KEY, MODULE.CHANGE_TI,
            )

    def test_module_has_no_reader_or_transmit_capability(self):
        source = MODULE_PATH.read_text()
        self.assertNotRegex(source, r"(?m)^\s*(from|import)\s+smartcard")
        self.assertNotIn(".transmit(", source)
        self.assertNotIn("connection.connect", source)


if __name__ == "__main__":
    unittest.main()

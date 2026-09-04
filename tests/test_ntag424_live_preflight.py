import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_live_preflight.py"
SPEC = importlib.util.spec_from_file_location("ntag424_live_preflight", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeConnection:
    def __init__(self, responses):
        self.responses = list(responses)
        self.apdus = []

    def transmit(self, apdu):
        self.apdus.append(bytes(apdu))
        return self.responses.pop(0)


class LivePreflightTests(unittest.TestCase):
    def test_mutating_commands_are_blocked(self):
        for instruction in MODULE.MUTATING_INSTRUCTIONS:
            with self.assertRaises(PermissionError):
                MODULE.require_preflight_command([0x90, instruction])

    def test_unknown_command_is_blocked(self):
        with self.assertRaises(PermissionError):
            MODULE.require_preflight_command([0x90, 0x00])

    def test_authentication_matches_nxp_vector(self):
        from ntag424_auth_key_validate import (
            AUTH_PART2_ENC,
            AUTH_RESPONSE_ENC,
            AUTH_RNDA,
            AUTH_RNDB_ENC,
            AUTH_TI,
            AUTH_ENC_KEY,
            AUTH_MAC_KEY,
        )

        connection = FakeConnection(
            [
                (list(AUTH_RNDB_ENC), 0x91, 0xAF),
                (list(AUTH_RESPONSE_ENC), 0x91, 0x00),
            ]
        )
        session = MODULE.authenticate_ev2_first(connection, rnd_a=AUTH_RNDA)

        self.assertEqual(session.ti, AUTH_TI)
        self.assertEqual(session.session_enc_key, AUTH_ENC_KEY)
        self.assertEqual(session.session_mac_key, AUTH_MAC_KEY)
        self.assertEqual(
            connection.apdus[0],
            bytes.fromhex("9071000002000000"),
        )
        self.assertEqual(
            connection.apdus[1],
            bytes.fromhex("90AF000020") + AUTH_PART2_ENC + bytes.fromhex("00"),
        )

    def test_modified_authentication_response_is_rejected(self):
        from ntag424_auth_key_validate import AUTH_RESPONSE_ENC, AUTH_RNDA, AUTH_RNDB_ENC

        modified = bytes([AUTH_RESPONSE_ENC[0] ^ 1]) + AUTH_RESPONSE_ENC[1:]
        connection = FakeConnection(
            [
                (list(AUTH_RNDB_ENC), 0x91, 0xAF),
                (list(modified), 0x91, 0x00),
            ]
        )
        with self.assertRaisesRegex(RuntimeError, "challenge"):
            MODULE.authenticate_ev2_first(connection, rnd_a=AUTH_RNDA)

    def test_version_uid_must_match(self):
        version = bytearray(28)
        version[0:2] = bytes.fromhex("0404")
        version[7:9] = bytes.fromhex("0404")
        version[14:21] = bytes.fromhex("044917DA291D90")
        MODULE.validate_version(bytes(version), bytes.fromhex("044917DA291D90"))

        with self.assertRaisesRegex(RuntimeError, "does not match"):
            MODULE.validate_version(bytes(version), bytes.fromhex("04000000000000"))

    def test_preflight_is_locked_to_factory_key_zero(self):
        with self.assertRaisesRegex(ValueError, "factory key 0"):
            MODULE.authenticate_ev2_first(FakeConnection([]), key_number=1)

    def test_generic_authentication_validates_key_inputs(self):
        with self.assertRaisesRegex(ValueError, "between 0 and 4"):
            MODULE.authenticate_ev2_first_with_key(None, 5, bytes(16))
        with self.assertRaisesRegex(ValueError, "16 bytes"):
            MODULE.authenticate_ev2_first_with_key(None, 1, bytes(15))

    def test_safety_check_does_not_open_reader(self):
        MODULE.safety_check()

    def test_no_mutating_instruction_is_allowlisted(self):
        allowlisted_ins = {ins for _, ins in MODULE.ALLOWED_COMMANDS}
        self.assertTrue(allowlisted_ins.isdisjoint(MODULE.MUTATING_INSTRUCTIONS))


if __name__ == "__main__":
    unittest.main()

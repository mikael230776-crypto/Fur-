import importlib.util
import pathlib
import unittest

MODULE_PATH = (
    pathlib.Path(__file__).parents[1] / "tools" / "ntag424_simulate_provision.py"
)
SPEC = importlib.util.spec_from_file_location("ntag424_simulate_provision", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

UID = "044917DA291D90"
KEYS = {number: bytes([number + 1]) * 16 for number in range(5)}


class SimulatedProvisioningTests(unittest.TestCase):
    def test_sun_verification_converts_mirrored_counter_to_lsb_first(self):
        uid = "04C767F2066180"
        mirrored_counter = "000001"
        key = bytes.fromhex("5ACE7E50AB65D5D51FD5BF5A16B8205B")
        session_key = MODULE.aes_cmac(
            key,
            bytes.fromhex("3CC30001008004C767F2066180010000"),
        )
        self.assertEqual(
            session_key.hex().upper(),
            "3A3E8110E05311F7A3FCF0D969BF2B48",
        )
        mac = MODULE.truncate_mac(MODULE.aes_cmac(session_key, b""))
        MODULE.verify_sun(uid, mirrored_counter, mac.hex(), key)

    def test_complete_sequence(self):
        tag = MODULE.SimulatedTag(uid=bytes.fromhex(UID))
        journal = MODULE.provision_simulated_tag(
            tag, "FUR-000001", UID, KEYS
        )

        self.assertEqual(journal.status, "COMPLETE")
        self.assertEqual(tag.keys, KEYS)
        self.assertEqual(tag.file_settings, MODULE.EXPECTED_SETTINGS)
        self.assertEqual(len(tag.ndef_file), 107)
        self.assertEqual(tag.authenticated_key, 0)
        self.assertEqual(tag.sdm_counter, 1)

    def test_key_zero_remains_factory_before_final_checkpoint(self):
        tag = MODULE.SimulatedTag(uid=bytes.fromhex(UID))
        with self.assertRaisesRegex(RuntimeError, "SIMULATED INTERRUPTION"):
            MODULE.provision_simulated_tag(
                tag,
                "FUR-000001",
                UID,
                KEYS,
                fail_after="sdm_settings_readback_verified",
            )
        self.assertEqual(tag.keys[0], MODULE.FACTORY_KEY)
        for number in range(1, 5):
            self.assertEqual(tag.keys[number], KEYS[number])

    def test_interruption_after_key_zero_requires_production_recovery(self):
        journal = MODULE.ProvisioningJournal()
        for checkpoint in MODULE.CHECKPOINTS[:5]:
            journal.record(checkpoint)
        self.assertEqual(
            journal.status,
            "RECOVERY REQUIRED WITH PRODUCTION KEY 0",
        )

    def test_wrong_uid_and_nonfactory_tag_stop_before_changes(self):
        tag = MODULE.SimulatedTag(uid=bytes.fromhex(UID))
        original = dict(tag.keys)
        with self.assertRaisesRegex(RuntimeError, "UID mismatch"):
            MODULE.provision_simulated_tag(
                tag, "FUR-000001", "04000000000000", KEYS
            )
        self.assertEqual(tag.keys, original)

        tag.file_settings = MODULE.EXPECTED_SETTINGS
        with self.assertRaisesRegex(RuntimeError, "factory settings"):
            MODULE.provision_simulated_tag(
                tag, "FUR-000001", UID, KEYS
            )
        self.assertEqual(tag.keys, original)

    def test_duplicate_keys_are_rejected(self):
        tag = MODULE.SimulatedTag(uid=bytes.fromhex(UID))
        keys = dict(KEYS)
        keys[4] = keys[3]
        with self.assertRaisesRegex(ValueError, "unique"):
            MODULE.provision_simulated_tag(
                tag, "FUR-000001", UID, keys
            )

    def test_sun_tampering_is_rejected(self):
        tag = MODULE.SimulatedTag(uid=bytes.fromhex(UID))
        tag.keys[1] = KEYS[1]
        tag.file_settings = MODULE.EXPECTED_SETTINGS
        uid, counter, mac = tag.generate_sun()
        bad_mac = ("00" if mac[:2] != "00" else "FF") + mac[2:]
        with self.assertRaisesRegex(RuntimeError, "SUN"):
            MODULE.verify_sun(uid, counter, bad_mac, KEYS[1])

    def test_every_pre_key_zero_interruption_retains_recovery_key(self):
        for checkpoint in MODULE.CHECKPOINTS[:4]:
            tag = MODULE.SimulatedTag(uid=bytes.fromhex(UID))
            with self.assertRaisesRegex(RuntimeError, "SIMULATED INTERRUPTION"):
                MODULE.provision_simulated_tag(
                    tag,
                    "FUR-000001",
                    UID,
                    KEYS,
                    fail_after=checkpoint,
                )
            self.assertEqual(tag.keys[0], MODULE.FACTORY_KEY)

    def test_source_has_no_reader_or_apdu_transport(self):
        source = MODULE_PATH.read_text()
        self.assertNotRegex(source, r"(?m)^\s*(from|import)\s+smartcard")
        self.assertNotIn(".transmit(", source)
        self.assertNotIn("connection.connect", source)


if __name__ == "__main__":
    unittest.main()

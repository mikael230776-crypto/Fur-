import importlib.util
import pathlib
import unittest
from dataclasses import replace

MODULE_PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_dry_run.py"
SPEC = importlib.util.spec_from_file_location("ntag424_dry_run", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProvisioningPlannerTests(unittest.TestCase):
    def test_nxp_vector(self):
        self.assertTrue(MODULE.nxp_cmac_self_test())

    def test_builds_expected_fur_profile(self):
        plan = MODULE.build_plan("fur-000001")

        self.assertEqual(plan.tag_id, "FUR-000001")
        self.assertIn("tagId=FUR-000001", plan.url)
        self.assertIn("&uid=00000000000000", plan.url)
        self.assertIn("&ctr=000000", plan.url)
        self.assertIn("&cmac=0000000000000000", plan.url)
        self.assertEqual(
            plan.ndef_file[0:2],
            (len(plan.ndef_file) - 2).to_bytes(2, "big"),
        )

        for name, placeholder in MODULE.PLACEHOLDERS.items():
            offset = plan.offsets[name]
            self.assertEqual(
                plan.ndef_file[offset : offset + len(placeholder)],
                placeholder.encode("ascii"),
            )

        self.assertEqual(plan.offsets, {"uid": 60, "ctr": 79, "cmac": 91})
        self.assertEqual(len(plan.ndef_file), 107)

    def test_builds_exact_change_file_settings_data(self):
        plan = MODULE.build_plan("FUR-000001")

        self.assertEqual(MODULE.FILE_OPTION.hex().upper(), "40")
        self.assertEqual(MODULE.ACCESS_RIGHTS.hex().upper(), "00E0")
        self.assertEqual(MODULE.SDM_OPTIONS.hex().upper(), "C1")
        self.assertEqual(MODULE.SDM_ACCESS_RIGHTS.hex().upper(), "F0E1")
        self.assertEqual(
            MODULE.build_change_file_settings_data(plan).hex().upper(),
            "4000E0C1F0E13C00004F00005B00005B0000",
        )

    def test_rejects_offset_that_misses_placeholder(self):
        plan = MODULE.build_plan("FUR-000001")
        invalid = replace(plan, offsets={**plan.offsets, "uid": plan.offsets["ctr"]})

        with self.assertRaisesRegex(ValueError, "uid offset"):
            MODULE.build_change_file_settings_data(invalid)

    def test_rejects_payload_over_capacity(self):
        plan = MODULE.build_plan("FUR-000001")
        invalid = replace(plan, ndef_file=plan.ndef_file + bytes(150))

        with self.assertRaisesRegex(ValueError, "capacity"):
            MODULE.build_change_file_settings_data(invalid)

    def test_rejects_invalid_tag_id(self):
        with self.assertRaises(ValueError):
            MODULE.build_plan("FUR-1")


if __name__ == "__main__":
    unittest.main()

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_execution_release.py"
SPEC = importlib.util.spec_from_file_location("ntag424_execution_release", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OneTimeExecutionReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "release.json"
        self.manifest = "a" * 64

    def tearDown(self):
        self.tmp.cleanup()

    @patch.object(MODULE.subprocess, "run")
    @patch.object(MODULE.subprocess, "check_output")
    @patch.object(MODULE.secrets, "token_hex", return_value="1" * 64)
    def test_release_is_bound_consumed_and_secret_not_written(
        self, token_hex, check_output, run
    ):
        check_output.side_effect = ["owner\n", "owner\n", "1" * 64 + "\n"]
        MODULE.arm_release(
            self.path, "044517DA291D90", self.manifest, now=1000
        )
        self.assertNotIn("1" * 64, self.path.read_text())
        release = MODULE.consume_release(
            self.path, "044517DA291D90", self.manifest, now=1100
        )
        self.assertEqual(release.expected_uid, "044517DA291D90")
        self.assertTrue(json.loads(self.path.read_text())["consumed"])
        with self.assertRaisesRegex(RuntimeError, "already"):
            MODULE.consume_release(
                self.path, "044517DA291D90", self.manifest, now=1100
            )

    @patch.object(MODULE.subprocess, "run")
    @patch.object(MODULE.subprocess, "check_output", return_value="owner\n")
    def test_wrong_uid_and_expiry_fail_closed(self, check_output, run):
        MODULE.arm_release(
            self.path, "044517DA291D90", self.manifest, ttl_seconds=60, now=1000
        )
        with self.assertRaisesRegex(RuntimeError, "UID mismatch"):
            MODULE.consume_release(
                self.path, "044917DA291D90", self.manifest, now=1010
            )
        with self.assertRaisesRegex(RuntimeError, "expired"):
            MODULE.consume_release(
                self.path, "044517DA291D90", self.manifest, now=1061
            )


if __name__ == "__main__":
    unittest.main()

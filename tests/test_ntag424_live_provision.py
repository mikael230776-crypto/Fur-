import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).parents[1] / "tools" / "ntag424_live_provision.py"
SPEC = importlib.util.spec_from_file_location("ntag424_live_provision", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LiveProvisionReleaseCandidateTests(unittest.TestCase):
    def test_execution_is_hard_locked(self):
        self.assertFalse(MODULE.LIVE_EXECUTION_ENABLED)

    def test_no_reader_transport_is_present(self):
        source = PATH.read_text()
        self.assertNotRegex(source, r"(?m)^\s*(from|import)\s+smartcard")
        self.assertNotIn(".transmit(", source)

    def test_release_check_composes_manifest_and_transport_gates(self):
        original_manifest = MODULE.build_manifest
        original_transport = MODULE.transport_safety_check
        MODULE.build_manifest = lambda *_: {"recovery_boundary": "key-0-last", "manifest_sha256": "a" * 64}
        MODULE.transport_safety_check = lambda: None
        try:
            result = MODULE.release_candidate_check("FUR-000001", "04112233445566")
            self.assertEqual(result["manifest_sha256"], "a" * 64)
        finally:
            MODULE.build_manifest = original_manifest
            MODULE.transport_safety_check = original_transport


if __name__ == "__main__":
    unittest.main()

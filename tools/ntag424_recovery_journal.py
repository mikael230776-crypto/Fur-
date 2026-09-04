#!/usr/bin/env python3
"""Persistent, key-free recovery journal for live NTAG 424 provisioning."""

import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

SCHEMA = "fur-ntag424-recovery-journal-v1"
CHECKPOINTS = (
    "preflight_verified",
    "key_1_changed_verified",
    "key_2_changed_verified",
    "key_3_changed_verified",
    "key_4_changed_verified",
    "ndef_readback_verified",
    "sdm_settings_readback_verified",
    "key_0_changed",
    "production_auth_and_sun_verified",
)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class PersistentRecoveryJournal:
    def __init__(self, path: Path, state: dict):
        self.path = Path(path)
        self.state = state
        self._validate()

    @classmethod
    def create(cls, path, tag_id, expected_uid, manifest_sha256):
        state = {
            "schema": SCHEMA,
            "tag_id": tag_id,
            "expected_uid": expected_uid.upper(),
            "manifest_sha256": manifest_sha256.lower(),
            "checkpoints": [],
            "pending": None,
        }
        journal = cls(Path(path), state)
        journal._save()
        return journal

    @classmethod
    def load(cls, path, tag_id, expected_uid, manifest_sha256):
        path = Path(path)
        state = json.loads(path.read_text(encoding="utf-8"))
        journal = cls(path, state)
        if (
            state["tag_id"] != tag_id
            or state["expected_uid"] != expected_uid.upper()
            or state["manifest_sha256"] != manifest_sha256.lower()
        ):
            raise RuntimeError("Recovery journal identity or manifest mismatch")
        return journal

    def _validate(self):
        required = {
            "schema", "tag_id", "expected_uid", "manifest_sha256", "checkpoints",
            "pending",
        }
        if set(self.state) != required or self.state["schema"] != SCHEMA:
            raise RuntimeError("Recovery journal schema is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", self.state["manifest_sha256"]) is None:
            raise RuntimeError("Recovery journal manifest hash is invalid")
        checkpoints = self.state["checkpoints"]
        if len(checkpoints) > len(CHECKPOINTS):
            raise RuntimeError("Recovery journal contains too many checkpoints")
        for index, entry in enumerate(checkpoints):
            if set(entry) != {"name", "verified", "evidence_sha256"}:
                raise RuntimeError("Recovery journal checkpoint is invalid")
            if entry["name"] != CHECKPOINTS[index] or entry["verified"] is not True:
                raise RuntimeError("Recovery journal checkpoint order is invalid")
            if re.fullmatch(r"[0-9a-f]{64}", entry["evidence_sha256"]) is None:
                raise RuntimeError("Recovery journal evidence hash is invalid")
        pending = self.state["pending"]
        if pending is not None:
            if len(checkpoints) >= len(CHECKPOINTS) or pending != CHECKPOINTS[len(checkpoints)]:
                raise RuntimeError("Recovery journal pending checkpoint is invalid")

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_bytes(_canonical(self.state) + b"\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)

    def begin(self, checkpoint):
        if self.state["pending"] is not None:
            raise RuntimeError("A recovery checkpoint is already pending")
        index = len(self.state["checkpoints"])
        if index >= len(CHECKPOINTS) or checkpoint != CHECKPOINTS[index]:
            raise RuntimeError("Recovery journal checkpoint is skipped or reordered")
        self.state["pending"] = checkpoint
        self._save()

    def confirm(self, checkpoint, evidence):
        if self.state["pending"] != checkpoint:
            raise RuntimeError("Recovery journal confirmation does not match pending checkpoint")
        if not isinstance(evidence, bytes) or not evidence:
            raise ValueError("Checkpoint evidence must be non-empty bytes")
        self.state["checkpoints"].append({
            "name": checkpoint,
            "verified": True,
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
        })
        self.state["pending"] = None
        self._save()

    def record(self, checkpoint, verified, evidence):
        if verified is not True:
            raise RuntimeError("Unverified checkpoint cannot be recorded")
        self.begin(checkpoint)
        self.confirm(checkpoint, evidence)

    @property
    def recovery_action(self):
        names = [entry["name"] for entry in self.state["checkpoints"]]
        if self.state["pending"] is not None:
            return f"INSPECT TAG STATE BEFORE RECOVERING {self.state['pending']}"
        if len(names) == len(CHECKPOINTS):
            return "COMPLETE"
        if names and names[-1] == "key_0_changed":
            return "RE-AUTHENTICATE WITH PRODUCTION KEY 0 AND VERIFY SUN"
        return f"RESUME AT {CHECKPOINTS[len(names)]} WITH FACTORY KEY 0 RETAINED"

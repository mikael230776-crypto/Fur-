#!/usr/bin/env python3
"""One-time, expiring execution release stored without exposing its secret."""

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

SCHEMA = "fur-ntag424-one-time-release-v1"
KEYCHAIN_SERVICE = "FUR NTAG 424 One-Time Execution Release"


@dataclass(frozen=True)
class ExecutionRelease:
    expected_uid: str
    manifest_sha256: str


def _account():
    return subprocess.check_output(["id", "-un"], text=True).strip()


def _save(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def arm_release(path, expected_uid, manifest_sha256, ttl_seconds=600, now=None):
    if not 60 <= ttl_seconds <= 900:
        raise ValueError("Release lifetime must be between 60 and 900 seconds")
    now = time.time() if now is None else now
    token = secrets.token_hex(32)
    account = _account()
    subprocess.run(
        [
            "security", "add-generic-password", "-a", account,
            "-s", KEYCHAIN_SERVICE, "-w", token, "-U",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    state = {
        "schema": SCHEMA,
        "expected_uid": expected_uid.upper(),
        "manifest_sha256": manifest_sha256.lower(),
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "expires_at": int(now + ttl_seconds),
        "consumed": False,
    }
    _save(path, state)


def consume_release(path, expected_uid, manifest_sha256, now=None):
    path = Path(path)
    state = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema", "expected_uid", "manifest_sha256", "token_sha256",
        "expires_at", "consumed",
    }
    if set(state) != required or state["schema"] != SCHEMA:
        raise RuntimeError("Execution release schema is invalid")
    if state["expected_uid"] != expected_uid.upper():
        raise RuntimeError("Execution release UID mismatch")
    if state["manifest_sha256"] != manifest_sha256.lower():
        raise RuntimeError("Execution release manifest mismatch")
    if state["consumed"] is not False:
        raise RuntimeError("Execution release has already been consumed")
    now = time.time() if now is None else now
    if now > state["expires_at"]:
        raise RuntimeError("Execution release has expired")
    account = _account()
    token = subprocess.check_output(
        [
            "security", "find-generic-password", "-a", account,
            "-s", KEYCHAIN_SERVICE, "-w",
        ],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
    if not hmac.compare_digest(
        hashlib.sha256(token.encode()).hexdigest(), state["token_sha256"]
    ):
        raise RuntimeError("Execution release secret is invalid")
    state["consumed"] = True
    _save(path, state)
    subprocess.run(
        [
            "security", "delete-generic-password", "-a", account,
            "-s", KEYCHAIN_SERVICE,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return ExecutionRelease(expected_uid.upper(), manifest_sha256.lower())

"""Shared fixtures for the Rekor monitor test suite.

All tests run offline: Rekor responses are built from the real log entry stored
in artifact.bundle, and requests.get is replaced with a fake.
"""

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

BUNDLE_PATH = REPO_ROOT / "artifact.bundle"
ARTIFACT_PATH = REPO_ROOT / "artifact.md"


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"HTTP {self.status_code}")


@pytest.fixture
def tlog_entry() -> dict[str, Any]:
    """The transparency log entry recorded in artifact.bundle."""
    bundle = json.loads(BUNDLE_PATH.read_text())
    entry: dict[str, Any] = bundle["verificationMaterial"]["tlogEntries"][0]
    return entry


@pytest.fixture
def rekor_entry(tlog_entry: dict[str, Any]) -> dict[str, Any]:
    """The same entry in the format returned by Rekor's /log/entries API."""
    proof = tlog_entry["inclusionProof"]
    return {
        "body": tlog_entry["canonicalizedBody"],
        "logIndex": int(tlog_entry["logIndex"]),
        "verification": {
            "inclusionProof": {
                "logIndex": int(proof["logIndex"]),
                "treeSize": int(proof["treeSize"]),
                "rootHash": base64.b64decode(proof["rootHash"]).hex(),
                "hashes": [base64.b64decode(h).hex() for h in proof["hashes"]],
            }
        },
    }


@pytest.fixture
def artifact_path() -> str:
    return str(ARTIFACT_PATH)

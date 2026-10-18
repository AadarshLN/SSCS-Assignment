"""Tests for the Rekor client functions and the CLI in main.py.

Network calls are replaced with FakeResponse objects so the suite runs offline.
"""

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import validate

import main
from merkle_proof import DefaultHasher
from tests.conftest import FakeResponse

TREE_ID = "1193050959916656506"

CHECKPOINT_SCHEMA = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array"},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"},
    },
    "required": ["inactiveShards", "rootHash", "signedTreeHead", "treeID", "treeSize"],
}


def _small_tree() -> tuple[str, str, str]:
    """Roots of a 2-leaf and 4-leaf tree, plus the 2 -> 4 consistency proof."""
    leaves = [DefaultHasher.hash_leaf(bytes([i])) for i in range(4)]
    left = DefaultHasher.hash_children(leaves[0], leaves[1])
    right = DefaultHasher.hash_children(leaves[2], leaves[3])
    root4 = DefaultHasher.hash_children(left, right)
    return left.hex(), root4.hex(), right.hex()


def _fake_rekor(
    monkeypatch: pytest.MonkeyPatch,
    entry: dict[str, Any] | None = None,
    checkpoint: dict[str, Any] | None = None,
    proof: dict[str, Any] | None = None,
) -> None:
    """Route requests.get calls in main.py to canned responses by URL."""

    def fake_get(url: str, **_: Any) -> FakeResponse:
        if url.endswith("/log/entries"):
            return FakeResponse({"uuid-123": entry})
        if url.endswith("/log/proof"):
            return FakeResponse(proof)
        if url.endswith("/log"):
            return FakeResponse(checkpoint)
        return FakeResponse({}, status_code=404)

    monkeypatch.setattr(main.requests, "get", fake_get)


def _checkpoint(size: int, root: str) -> dict[str, Any]:
    return {
        "inactiveShards": [],
        "rootHash": root,
        "signedTreeHead": "rekor.sigstore.dev - 1193050959916656506\n...",
        "treeID": TREE_ID,
        "treeSize": size,
    }


# ---------- Rekor client functions ----------


def test_get_log_entry_returns_entry(
    monkeypatch: pytest.MonkeyPatch, rekor_entry: dict[str, Any]
) -> None:
    _fake_rekor(monkeypatch, entry=rekor_entry)
    assert main.get_log_entry(123, debug=True) == rekor_entry


def test_get_latest_checkpoint_debug_writes_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _fake_rekor(monkeypatch, checkpoint=_checkpoint(4, "ab" * 32))
    monkeypatch.chdir(tmp_path)
    checkpoint = main.get_latest_checkpoint(debug=True)
    validate(instance=checkpoint, schema=CHECKPOINT_SCHEMA)
    assert json.loads((tmp_path / "checkpoint.json").read_text()) == checkpoint


def test_http_error_is_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        main.requests, "get", lambda url, **_: FakeResponse({}, status_code=500)
    )
    with pytest.raises(main.requests.HTTPError):
        main.get_latest_checkpoint()


# ---------- Inclusion ----------


def test_inclusion_succeeds_for_real_entry(
    monkeypatch: pytest.MonkeyPatch, rekor_entry: dict[str, Any], artifact_path: str
) -> None:
    _fake_rekor(monkeypatch, entry=rekor_entry)
    assert main.inclusion(123, artifact_path, debug=True) is True


def test_inclusion_fails_for_tampered_artifact(
    monkeypatch: pytest.MonkeyPatch, rekor_entry: dict[str, Any], tmp_path: Path
) -> None:
    _fake_rekor(monkeypatch, entry=rekor_entry)
    tampered = tmp_path / "artifact.md"
    tampered.write_text("not the signed content\n")
    assert main.inclusion(123, str(tampered)) is False


def test_inclusion_fails_for_bad_proof(
    monkeypatch: pytest.MonkeyPatch, rekor_entry: dict[str, Any], artifact_path: str
) -> None:
    rekor_entry["verification"]["inclusionProof"]["rootHash"] = "00" * 32
    _fake_rekor(monkeypatch, entry=rekor_entry)
    assert main.inclusion(123, artifact_path) is False


def test_inclusion_fails_for_entry_without_signature(
    monkeypatch: pytest.MonkeyPatch, rekor_entry: dict[str, Any], artifact_path: str
) -> None:
    rekor_entry["body"] = "e30="  # base64 of "{}"
    _fake_rekor(monkeypatch, entry=rekor_entry)
    assert main.inclusion(123, artifact_path) is False


@pytest.mark.parametrize(("index", "path"), [(-1, "artifact.md"), (1, "missing.md")])
def test_inclusion_rejects_invalid_arguments(index: int, path: str) -> None:
    with pytest.raises(ValueError):
        main.inclusion(index, path)


# ---------- Consistency ----------


def test_consistency_succeeds_for_valid_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    root2, root4, proof_hash = _small_tree()
    _fake_rekor(
        monkeypatch,
        checkpoint=_checkpoint(4, root4),
        proof={"hashes": [proof_hash]},
    )
    prev = {"treeID": TREE_ID, "treeSize": 2, "rootHash": root2}
    assert main.consistency(prev) is True


def test_consistency_detects_tampered_log(monkeypatch: pytest.MonkeyPatch) -> None:
    root2, _, proof_hash = _small_tree()
    _fake_rekor(
        monkeypatch,
        checkpoint=_checkpoint(4, "ff" * 32),
        proof={"hashes": [proof_hash]},
    )
    prev = {"treeID": TREE_ID, "treeSize": 2, "rootHash": root2}
    assert main.consistency(prev) is False


def test_consistency_uses_inactive_shard(monkeypatch: pytest.MonkeyPatch) -> None:
    root2, root4, proof_hash = _small_tree()
    latest = _checkpoint(100, "aa" * 32)
    latest["treeID"] = "999"
    latest["inactiveShards"] = [_checkpoint(4, root4)]
    _fake_rekor(monkeypatch, checkpoint=latest, proof={"hashes": [proof_hash]})
    prev = {"treeID": TREE_ID, "treeSize": 2, "rootHash": root2}
    assert main.consistency(prev) is True


def test_consistency_unknown_tree_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_rekor(monkeypatch, checkpoint=_checkpoint(4, "aa" * 32))
    prev = {"treeID": "42", "treeSize": 2, "rootHash": "bb" * 32}
    assert main.consistency(prev) is False


def test_consistency_rejects_incomplete_checkpoint() -> None:
    with pytest.raises(ValueError):
        main.consistency({"treeID": TREE_ID, "treeSize": 2})


# ---------- CLI ----------


def _run_cli(monkeypatch: pytest.MonkeyPatch, *args: str) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    main.main()


def test_cli_checkpoint_prints_valid_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _fake_rekor(monkeypatch, checkpoint=_checkpoint(4, "ab" * 32))
    _run_cli(monkeypatch, "-c")
    validate(instance=json.loads(capsys.readouterr().out), schema=CHECKPOINT_SCHEMA)


def test_cli_inclusion_exits_nonzero_on_failure(
    monkeypatch: pytest.MonkeyPatch, rekor_entry: dict[str, Any], tmp_path: Path
) -> None:
    _fake_rekor(monkeypatch, entry=rekor_entry)
    tampered = tmp_path / "artifact.md"
    tampered.write_text("tampered\n")
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(monkeypatch, "--inclusion", "123", "--artifact", str(tampered))
    assert excinfo.value.code == 1


def test_cli_consistency_success(monkeypatch: pytest.MonkeyPatch) -> None:
    root2, root4, proof_hash = _small_tree()
    _fake_rekor(
        monkeypatch, checkpoint=_checkpoint(4, root4), proof={"hashes": [proof_hash]}
    )
    _run_cli(
        monkeypatch,
        "-d",
        "--consistency",
        "--tree-id",
        TREE_ID,
        "--tree-size",
        "2",
        "--root-hash",
        root2,
    )


def test_cli_consistency_exits_nonzero_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root2, _, proof_hash = _small_tree()
    _fake_rekor(
        monkeypatch,
        checkpoint=_checkpoint(4, "ff" * 32),
        proof={"hashes": [proof_hash]},
    )
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(
            monkeypatch,
            "--consistency",
            "--tree-id",
            TREE_ID,
            "--tree-size",
            "2",
            "--root-hash",
            root2,
        )
    assert excinfo.value.code == 1


@pytest.mark.parametrize(
    "args",
    [
        ["--consistency"],
        ["--consistency", "--tree-id", "abc"],
        ["--consistency", "--tree-id", TREE_ID],
        ["--consistency", "--tree-id", TREE_ID, "--tree-size", "0"],
        ["--consistency", "--tree-id", TREE_ID, "--tree-size", "5"],
        [
            "--consistency",
            "--tree-id",
            TREE_ID,
            "--tree-size",
            "5",
            "--root-hash",
            "not-hex",
        ],
    ],
)
def test_cli_rejects_invalid_consistency_arguments(
    monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(monkeypatch, *args)
    assert excinfo.value.code == 2

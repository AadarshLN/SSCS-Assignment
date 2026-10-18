"""Tests for RFC 6962 hashing and Merkle proof verification."""

import base64
import hashlib
from typing import Any

import pytest

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)


def _tree_of_four() -> tuple[bytes, bytes, bytes]:
    """Return (root of first 2 leaves, root of all 4 leaves, MTH(leaves 2..3))."""
    leaves = [DefaultHasher.hash_leaf(bytes([i])) for i in range(4)]
    left = DefaultHasher.hash_children(leaves[0], leaves[1])
    right = DefaultHasher.hash_children(leaves[2], leaves[3])
    return left, DefaultHasher.hash_children(left, right), right


def test_hash_leaf_uses_rfc6962_leaf_prefix() -> None:
    expected = hashlib.sha256(b"\x00" + b"hello").digest()
    assert DefaultHasher.hash_leaf(b"hello") == expected


def test_hash_children_uses_rfc6962_node_prefix() -> None:
    left, right = b"\x01" * 32, b"\x02" * 32
    expected = hashlib.sha256(b"\x01" + left + right).digest()
    assert DefaultHasher.hash_children(left, right) == expected
    assert DefaultHasher.size() == 32


def test_compute_leaf_hash_matches_hash_leaf() -> None:
    body = base64.b64encode(b'{"kind":"hashedrekord"}').decode()
    expected = DefaultHasher.hash_leaf(b'{"kind":"hashedrekord"}').hex()
    assert compute_leaf_hash(body) == expected


def test_verify_inclusion_with_real_rekor_proof(rekor_entry: dict[str, Any]) -> None:
    proof = rekor_entry["verification"]["inclusionProof"]
    leaf_hash = compute_leaf_hash(rekor_entry["body"])
    # Raises on failure; returning normally means the proof is valid.
    verify_inclusion(
        DefaultHasher,
        proof["logIndex"],
        proof["treeSize"],
        leaf_hash,
        proof["hashes"],
        proof["rootHash"],
        debug=True,
    )


def test_verify_inclusion_rejects_wrong_root(rekor_entry: dict[str, Any]) -> None:
    proof = rekor_entry["verification"]["inclusionProof"]
    leaf_hash = compute_leaf_hash(rekor_entry["body"])
    with pytest.raises(RootMismatchError) as excinfo:
        verify_inclusion(
            DefaultHasher,
            proof["logIndex"],
            proof["treeSize"],
            leaf_hash,
            proof["hashes"],
            "00" * 32,
        )
    # Hashes must be shown as plain hex, not b'...'
    assert "b'" not in str(excinfo.value)
    assert "00" * 32 in str(excinfo.value)


def test_verify_inclusion_rejects_index_beyond_tree_size() -> None:
    with pytest.raises(ValueError, match="beyond size"):
        verify_inclusion(DefaultHasher, 5, 5, "00" * 32, [], "00" * 32)


def test_verify_consistency_valid_proof() -> None:
    root2_leaves, root4_leaves, right_subtree = _tree_of_four()
    verify_consistency(
        DefaultHasher,
        2,
        4,
        [right_subtree.hex()],
        root2_leaves.hex(),
        root4_leaves.hex(),
    )


def test_verify_consistency_detects_tampered_root() -> None:
    root2_leaves, _, right_subtree = _tree_of_four()
    with pytest.raises(RootMismatchError):
        verify_consistency(
            DefaultHasher, 2, 4, [right_subtree.hex()], root2_leaves.hex(), "ff" * 32
        )


@pytest.mark.parametrize(
    ("size1", "size2", "proof", "message"),
    [
        (4, 2, [], "size2"),
        (2, 2, ["aa" * 32], "not empty"),
        (0, 4, ["aa" * 32], "expected empty"),
        (2, 4, [], "empty bytearray_proof"),
        (2, 4, ["aa" * 32, "bb" * 32], "wrong bytearray_proof size"),
    ],
)
def test_verify_consistency_rejects_malformed_input(
    size1: int, size2: int, proof: list[str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        verify_consistency(DefaultHasher, size1, size2, proof, "00" * 32, "00" * 32)

"""Rekor transparency log monitor: inclusion and consistency verification."""

import argparse
import base64
import json
import os
import sys
from typing import Any

import requests

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from util import extract_public_key, verify_artifact_signature

REKOR_BASE_URL = "https://rekor.sigstore.dev/api/v1"
REQUEST_TIMEOUT = 15


def get_log_entry(log_index: int, debug: bool = False) -> dict[str, Any]:
    """Fetch the log entry at log_index from Rekor."""
    response = requests.get(
        f"{REKOR_BASE_URL}/log/entries",
        params={"logIndex": log_index},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    data: dict[str, Any] = response.json()

    entry: dict[str, Any] = next(iter(data.values()))
    if debug:
        print(json.dumps(entry, indent=4))
    return entry


def get_verification_proof(
    log_index: int, debug: bool = False, entry: dict[str, Any] | None = None
) -> tuple[dict[str, Any], str]:
    """Return the inclusion proof and computed leaf hash for a log entry."""
    if entry is None:
        entry = get_log_entry(log_index, debug)
    proof: dict[str, Any] = entry["verification"]["inclusionProof"]
    leaf_hash = compute_leaf_hash(entry["body"])
    if debug:
        print("leaf hash:", leaf_hash)
        print(json.dumps(proof, indent=4))
    return proof, leaf_hash


def inclusion(
    log_index: int, artifact_filepath: str | None, debug: bool = False
) -> bool:
    """Verify the artifact signature and its inclusion in the Rekor log."""
    # verify that log index and artifact filepath values are sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Invalid log index")
    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        raise ValueError("Invalid artifact filepath")

    entry = get_log_entry(log_index, debug)
    try:
        body = json.loads(base64.b64decode(entry["body"]))
        signature = base64.b64decode(body["spec"]["signature"]["content"])
        certificate = base64.b64decode(
            body["spec"]["signature"]["publicKey"]["content"]
        )
        public_key = extract_public_key(certificate)
    except (KeyError, ValueError) as e:
        print(
            "Could not read signature or certificate from log entry",
            log_index,
            ":",
            e,
        )
        return False

    if not verify_artifact_signature(signature, public_key, artifact_filepath):
        print(
            "Verification failed for log index",
            log_index,
            "and artifact",
            artifact_filepath,
        )
        return False

    proof, leaf_hash = get_verification_proof(log_index, debug, entry)
    try:
        verify_inclusion(
            DefaultHasher,
            proof["logIndex"],
            proof["treeSize"],
            leaf_hash,
            proof["hashes"],
            proof["rootHash"],
            debug,
        )
    except (RootMismatchError, ValueError) as e:
        print("Inclusion proof verification failed:", e)
        return False
    print(
        "Offline verification successful for log index",
        log_index,
        "and artifact",
        artifact_filepath,
    )
    return True


def get_latest_checkpoint(debug: bool = False) -> dict[str, Any]:
    """Fetch the latest checkpoint from Rekor (saved to checkpoint.json in debug)."""
    response = requests.get(f"{REKOR_BASE_URL}/log", timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    checkpoint: dict[str, Any] = response.json()
    if debug:
        with open("checkpoint.json", "w") as f:
            json.dump(checkpoint, f, indent=4)
    return checkpoint


def consistency(prev_checkpoint: dict[str, Any], debug: bool = False) -> bool:
    """Verify that prev_checkpoint is consistent with the latest checkpoint."""
    # verify that prev checkpoint is not empty
    if not prev_checkpoint or not all(
        prev_checkpoint.get(k) for k in ("treeID", "treeSize", "rootHash")
    ):
        raise ValueError("Previous checkpoint is empty or incomplete")
    latest = get_latest_checkpoint(debug)

    target: dict[str, Any] | None = None
    if str(latest["treeID"]) == str(prev_checkpoint["treeID"]):
        target = latest
    else:
        for shard in latest.get("inactiveShards", []):
            if str(shard["treeID"]) == str(prev_checkpoint["treeID"]):
                target = shard
                break
    if target is None:
        print("Tree ID not found in active or inactive shards")
        return False

    if target["treeSize"] == prev_checkpoint["treeSize"]:
        print("Warning: checkpoints are identical; wait for the log to grow")

    response = requests.get(
        f"{REKOR_BASE_URL}/log/proof",
        params={
            "firstSize": prev_checkpoint["treeSize"],
            "lastSize": target["treeSize"],
            "treeID": prev_checkpoint["treeID"],
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    proof = response.json()

    try:
        verify_consistency(
            DefaultHasher,
            prev_checkpoint["treeSize"],
            target["treeSize"],
            proof["hashes"],
            prev_checkpoint["rootHash"],
            target["rootHash"],
        )
    except (RootMismatchError, ValueError) as e:
        print("Consistency verification failed:", e)
        return False

    print("Consistency verification successful")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help=(
            "Verify inclusion of an entry in the Rekor Transparency Log using "
            "log index and artifact filename. Usage: --inclusion 126574567"
        ),
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact", help="Artifact filepath for verifying signature", required=False
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()

    debug: bool = args.debug
    if debug:
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion is not None:
        if not inclusion(args.inclusion, args.artifact, debug):
            sys.exit(1)
    if args.consistency:
        if not args.tree_id:
            parser.error("please specify tree id for prev checkpoint")
        if (
            not (args.tree_id.isascii() and args.tree_id.isdigit())
            or not 0 < int(args.tree_id) < 2**63
        ):
            parser.error("--tree-id must be a positive 64-bit integer")

        if args.tree_size is None:
            parser.error("please specify tree size for prev checkpoint")
        if args.tree_size < 1:
            parser.error("--tree-size must be a positive integer")

        if not args.root_hash:
            parser.error("please specify root hash for prev checkpoint")
        try:
            if len(bytes.fromhex(args.root_hash)) != 32:
                raise ValueError
        except ValueError:
            parser.error("--root-hash must be a 64-character hex SHA-256 digest")

        prev_checkpoint: dict[str, Any] = {
            "treeID": args.tree_id,
            "treeSize": args.tree_size,
            "rootHash": args.root_hash,
        }

        if not consistency(prev_checkpoint, debug):
            sys.exit(1)


if __name__ == "__main__":
    main()

import argparse
import json
import os
import requests
import base64
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    
    response = requests.get("https://rekor.sigstore.dev/api/v1/log/entries", params={"logIndex": log_index}, timeout=15)

    response.raise_for_status()
    data = response.json()

    entry = next(iter(data.values()))
    if debug:
        print(json.dumps(entry,indent=4))
    return entry


def get_verification_proof(log_index, debug=False, entry=None):
    if entry is None:
        entry = get_log_entry(log_index,debug)
    proof = entry['verification']['inclusionProof']
    leaf_hash = compute_leaf_hash(entry['body'])
    if debug:
        print("leaf hash:", leaf_hash)
        print(json.dumps(proof, indent=4))
    return proof, leaf_hash

    

def inclusion(log_index, artifact_filepath, debug=False):
    

    # verify that log index and artifact filepath values are sane
    if not isinstance(log_index,int) or log_index < 0:
        raise ValueError("Invalid log index")
        return
    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        raise ValueError("Invalid artifact filepath")
        return
    
    entry = get_log_entry(log_index, debug)
    body = json.loads(base64.b64decode(entry["body"]))
    signature = base64.b64decode(body["spec"]["signature"]["content"])
    certificate = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])

    public_key = extract_public_key(certificate)
    verify_artifact_signature(signature, public_key, artifact_filepath)
    
    proof, leaf_hash = get_verification_proof(log_index, debug, entry)
    verify_inclusion(DefaultHasher, 
    proof["logIndex"], 
    proof["treeSize"], 
    leaf_hash, 
    proof['hashes'], 
    proof['rootHash'],debug)
    print("Offline verification successful for log index", log_index, "and artifact", artifact_filepath)
    

def get_latest_checkpoint(debug=False):
    response = requests.get("https://rekor.sigstore.dev/api/v1/log", timeout=15)
    response.raise_for_status()
    checkpoint = response.json()
    if debug:
        with open("checkpoint.json", "w") as f:
            json.dump(checkpoint, f, indent=5)
    return checkpoint
    



def consistency(prev_checkpoint, debug=False):
    
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    if not prev_checkpoint or not all (prev_checkpoint.get(k) for k in ("treeID", "treeSize", "rootHash")):
        raise ValueError("Previous checkpoint is empty or incomplete")
        return
    latest = get_latest_checkpoint(debug)

    target = None
    if str(latest["treeID"]) == str(prev_checkpoint["treeID"]):
        target = latest
    else:
        for shard in latest.get("inactiveShards", []):
            if str(shard["treeID"]) == str(prev_checkpoint["treeID"]):
                target = shard
                break
    if target is None:
        print("Tree ID not found in active or inactive shards")
        return 
    

    if target['treeSize'] == prev_checkpoint['treeSize']:
       print("Warning: checkpoints are identical; wait for the log to grow")



    response = requests.get("https://rekor.sigstore.dev/api/v1/log/proof",
                            params={"firstSize": prev_checkpoint["treeSize"],
                                    "lastSize": target["treeSize"],
                                    "treeID": prev_checkpoint["treeID"]},
                            timeout=15)

    response.raise_for_status()
    proof = response.json()

    verify_consistency(DefaultHasher,
                       prev_checkpoint["treeSize"],
                       target["treeSize"],
                       proof["hashes"],
                       prev_checkpoint["rootHash"],
                       target["rootHash"])

    
    print("Consistency verification successful")




def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()

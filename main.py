import argparse
import base64
import json
import os

import requests

from merkle_proof import (
    DefaultHasher,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from util import extract_public_key, verify_artifact_signature

REKOR = "https://rekor.sigstore.dev/api/v1"


def get_log_entry(log_index, debug=False):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log index must be a non-negative integer")

    response = requests.get(
        f"{REKOR}/log/entries",
        params={"logIndex": log_index},
        timeout=10,
    )
    response.raise_for_status()

    entry = next(iter(response.json().values()))

    if debug:
        print(json.dumps(entry, indent=2))

    return entry

def get_verification_proof(log_index, debug=False):
    return get_log_entry(log_index, debug)["verification"]["inclusionProof"]

def inclusion(log_index, artifact_filepath, debug=False):
    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        raise ValueError("artifact file not found")

    entry = get_log_entry(log_index, debug)

    body = json.loads(base64.b64decode(entry["body"]))
    signature = base64.b64decode(body["spec"]["signature"]["content"])
    cert_pem = base64.b64decode(
        body["spec"]["signature"]["publicKey"]["content"]
    )

    public_key = extract_public_key(cert_pem)
    verify_artifact_signature(signature, public_key, artifact_filepath)

    proof = entry["verification"]["inclusionProof"]
    leaf_hash = compute_leaf_hash(entry["body"])

    verify_inclusion(
        DefaultHasher,
        proof["logIndex"],
        proof["treeSize"],
        leaf_hash,
        proof["hashes"],
        proof["rootHash"],
        debug,
    )

    print("Offline root hash calculation for inclusion verified.")

def get_latest_checkpoint(debug=False):
    response = requests.get(f"{REKOR}/log", timeout=10)
    response.raise_for_status()

    checkpoint = response.json()
    checkpoint.pop("inactiveShards", None)

    if debug:
        with open("checkpoint.json", "w") as checkpoint_file:
            json.dump(checkpoint, checkpoint_file, indent=4)

    return checkpoint

def consistency(prev_checkpoint, debug=False):
    if not prev_checkpoint or not all(prev_checkpoint.values()):
        raise ValueError("previous checkpoint is empty")

    latest = get_latest_checkpoint(debug)

    if str(prev_checkpoint["treeID"]) != str(latest["treeID"]):
        raise ValueError("old checkpoint is from a different tree (shard)")

    response = requests.get(
        f"{REKOR}/log/proof",
        params={
            "firstSize": prev_checkpoint["treeSize"],
            "lastSize": latest["treeSize"],
            "treeID": prev_checkpoint["treeID"],
        },
        timeout=10,
    )
    response.raise_for_status()

    proof = response.json()

    verify_consistency(
        DefaultHasher,
        prev_checkpoint["treeSize"],
        latest["treeSize"],
        proof["hashes"],
        prev_checkpoint["rootHash"],
        latest["rootHash"],
    )

    print("Consistency verification successful.")

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

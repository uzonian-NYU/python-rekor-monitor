"""Record Rekor responses for offline tests."""

import json
from pathlib import Path

import requests

REKOR = "https://rekor.sigstore.dev/api/v1"
LOG_INDEX = 3082335568
OLD_CHECKPOINT = {
    "treeID": "1193050959916656506",
    "treeSize": 2977172459,
    "rootHash": "81f8fa37bf67fd1cfb8170036c33098af8a5dda4dc1295f71f151d7813aa14e9",
}
OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def main() -> None:
    """Fetch and save the responses needed by the tests."""
    entry = requests.get(
        f"{REKOR}/log/entries",
        params={"logIndex": LOG_INDEX},
        timeout=30,
    )
    entry.raise_for_status()

    latest = requests.get(f"{REKOR}/log", timeout=30)
    latest.raise_for_status()
    latest_json = latest.json()

    if str(latest_json["treeID"]) != OLD_CHECKPOINT["treeID"]:
        raise ValueError("Latest checkpoint belongs to a different tree.")

    proof = requests.get(
        f"{REKOR}/log/proof",
        params={
            "firstSize": OLD_CHECKPOINT["treeSize"],
            "lastSize": latest_json["treeSize"],
            "treeID": OLD_CHECKPOINT["treeID"],
        },
        timeout=30,
    )
    proof.raise_for_status()

    payloads = {
        "entry.json": entry.json(),
        "latest_checkpoint.json": latest_json,
        "consistency_proof.json": proof.json(),
        "old_checkpoint.json": OLD_CHECKPOINT,
    }

    OUT.mkdir(parents=True, exist_ok=True)
    for name, payload in payloads.items():
        (OUT / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Wrote fixtures to {OUT}")


if __name__ == "__main__":
    main()

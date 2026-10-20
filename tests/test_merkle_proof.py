"""Tests for Merkle hashing, inclusion, and consistency."""

import base64
import hashlib

import pytest

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    root_from_inclusion_proof,
    verify_consistency,
    verify_inclusion,
)


def test_compute_leaf_hash(entry):
    raw = base64.b64decode(entry["body"])
    expected = hashlib.sha256(b"\x00" + raw).hexdigest()

    assert compute_leaf_hash(entry["body"]) == expected


def test_hasher_operations():
    hasher = DefaultHasher

    assert hasher.size() == 32
    assert hasher.empty_root() == hashlib.sha256(b"").digest()
    assert hasher.hash_leaf(b"example") == hashlib.sha256(b"\x00example").digest()
    assert hasher.hash_children(b"left", b"right") == hashlib.sha256(b"\x01leftright").digest()


def test_real_inclusion_proof(entry, capsys):
    proof = entry["verification"]["inclusionProof"]

    verify_inclusion(
        DefaultHasher,
        proof["logIndex"],
        proof["treeSize"],
        compute_leaf_hash(entry["body"]),
        proof["hashes"],
        proof["rootHash"],
        debug=True,
    )

    assert "Calculated root hash" in capsys.readouterr().out


def test_inclusion_rejects_wrong_root(entry):
    proof = entry["verification"]["inclusionProof"]

    with pytest.raises(RootMismatchError) as error:
        verify_inclusion(
            DefaultHasher,
            proof["logIndex"],
            proof["treeSize"],
            compute_leaf_hash(entry["body"]),
            proof["hashes"],
            "ff" * 32,
        )

    assert "does not match expected root" in str(error.value)


@pytest.mark.parametrize(
    "index, size, leaf, proof",
    [
        (1, 1, b"x" * 32, []),
        (0, 1, b"short", []),
        (0, 2, b"x" * 32, []),
    ],
)
def test_inclusion_rejects_invalid_inputs(index, size, leaf, proof):
    with pytest.raises(ValueError):
        root_from_inclusion_proof(DefaultHasher, index, size, leaf, proof)


def test_real_consistency_proof(old_checkpoint, latest_checkpoint, consistency_proof):
    verify_consistency(
        DefaultHasher,
        old_checkpoint["treeSize"],
        latest_checkpoint["treeSize"],
        consistency_proof["hashes"],
        old_checkpoint["rootHash"],
        latest_checkpoint["rootHash"],
    )


def test_consistency_rejects_wrong_old_root(old_checkpoint, latest_checkpoint, consistency_proof):
    with pytest.raises(RootMismatchError):
        verify_consistency(
            DefaultHasher,
            old_checkpoint["treeSize"],
            latest_checkpoint["treeSize"],
            consistency_proof["hashes"],
            "ff" * 32,
            latest_checkpoint["rootHash"],
        )


def test_consistency_accepts_equal_trees():
    verify_consistency(DefaultHasher, 7, 7, [], "ab" * 32, "ab" * 32)

    with pytest.raises(RootMismatchError):
        verify_consistency(DefaultHasher, 7, 7, [], "ab" * 32, "cd" * 32)


def test_consistency_accepts_empty_old_tree():
    verify_consistency(DefaultHasher, 0, 5, [], "00" * 32, "ab" * 32)


@pytest.mark.parametrize(
    "first_size, last_size, proof",
    [
        (10, 5, []),
        (7, 7, ["ab" * 32]),
        (0, 5, ["ab" * 32]),
        (1, 2, []),
    ],
)
def test_consistency_rejects_invalid_inputs(first_size, last_size, proof):
    with pytest.raises(ValueError):
        verify_consistency(
            DefaultHasher,
            first_size,
            last_size,
            proof,
            "ab" * 32,
            "ab" * 32,
        )

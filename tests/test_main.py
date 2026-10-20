"""Offline tests for the main verification program."""

import json
import sys

import pytest
from cryptography.exceptions import InvalidSignature

import main


def test_get_log_entry(fake_rekor, entry, capsys):
    result = main.get_log_entry(3082335568, debug=True)

    assert result == entry
    assert json.loads(capsys.readouterr().out) == entry


def test_negative_log_index_is_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        main.get_log_entry(-1)


def test_get_verification_proof(fake_rekor, entry):
    assert main.get_verification_proof(3082335568) == (entry["verification"]["inclusionProof"])


def test_inclusion_succeeds(fake_rekor, artifact_path, capsys):
    main.inclusion(3082335568, str(artifact_path))

    output = capsys.readouterr().out
    assert "Signature verified." in output
    assert "Offline root hash calculation for inclusion verified." in output


def test_inclusion_rejects_changed_artifact(fake_rekor, tmp_path, capsys):
    changed = tmp_path / "changed.txt"
    changed.write_text("Not the original artifact.\n", encoding="utf-8")

    with pytest.raises(InvalidSignature):
        main.inclusion(3082335568, str(changed))

    assert "inclusion verified" not in capsys.readouterr().out


def test_inclusion_requires_existing_file(tmp_path):
    missing = tmp_path / "missing.txt"

    with pytest.raises(ValueError, match="artifact file not found"):
        main.inclusion(3082335568, str(missing))


def test_checkpoint_keeps_fields_without_writing_file(
    fake_rekor, latest_checkpoint, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)

    result = main.get_latest_checkpoint(debug=True)

    assert result == latest_checkpoint
    assert "inactiveShards" in result
    assert not (tmp_path / "checkpoint.json").exists()


def test_consistency_succeeds(fake_rekor, old_checkpoint, capsys):
    main.consistency(old_checkpoint)

    assert "Consistency verification successful." in capsys.readouterr().out


def test_consistency_rejects_empty_checkpoint():
    with pytest.raises(ValueError, match="previous checkpoint is empty"):
        main.consistency({})


def test_consistency_rejects_different_tree(fake_rekor, old_checkpoint):
    different = dict(old_checkpoint, treeID="different-tree")

    with pytest.raises(ValueError, match="different tree"):
        main.consistency(different)


def test_cli_checkpoint(fake_rekor, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "-c"])

    main.main()

    result = json.loads(capsys.readouterr().out)
    assert {"treeID", "treeSize", "rootHash", "inactiveShards"} <= result.keys()


def test_cli_verification(fake_rekor, artifact_path, old_checkpoint, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "-d",
            "--inclusion",
            "3082335568",
            "--artifact",
            str(artifact_path),
            "--consistency",
            "--tree-id",
            str(old_checkpoint["treeID"]),
            "--tree-size",
            str(old_checkpoint["treeSize"]),
            "--root-hash",
            old_checkpoint["rootHash"],
        ],
    )

    main.main()

    output = capsys.readouterr().out
    assert "Signature verified." in output
    assert "inclusion verified" in output
    assert "Consistency verification successful." in output


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["--inclusion", "3082335568"], "please specify artifact filepath"),
        (["--consistency"], "please specify tree id"),
        (["--consistency", "--tree-id", "1"], "please specify tree size"),
        (
            ["--consistency", "--tree-id", "1", "--tree-size", "5"],
            "please specify root hash",
        ),
    ],
)
def test_cli_reports_missing_arguments(monkeypatch, capsys, arguments, message):
    monkeypatch.setattr(sys, "argv", ["main.py", *arguments])

    main.main()

    assert message in capsys.readouterr().out

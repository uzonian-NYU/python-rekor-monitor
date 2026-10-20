# python-rekor-monitor

A Python command-line tool for checking entries in the
[Sigstore Rekor transparency log](https://docs.sigstore.dev/logging/overview/).

Built for NYU CS-GY 9223 Software Supply Chain Security.

## What it checks

- **Artifact signature:** checks the artifact using the public key from the
  certificate or key stored in the Rekor entry.
- **Inclusion:** checks the Merkle proof showing that an entry belongs to the log.
- **Consistency:** checks that the log grew consistently between two checkpoints.

## Installation

Requires Python 3.10 or newer and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/uzonian-NYU/python-rekor-monitor.git
cd python-rekor-monitor
poetry install
```

## Usage

Verify the Assignment 1 artifact:

```bash
poetry run python main.py --inclusion 3082335568 --artifact artifact.md
```

Expected output:

```text
Signature verified.
Offline root hash calculation for inclusion verified.
```

Fetch the latest checkpoint:

```bash
poetry run python main.py -c
```

Verify consistency using a previously saved checkpoint:

```bash
poetry run python main.py --consistency \
  --tree-id <treeID> \
  --tree-size <treeSize> \
  --root-hash <rootHash>
```

Add `--debug` for diagnostic output. Debug mode does not save or overwrite
checkpoint files.

## Project layout

| Path | Purpose |
| --- | --- |
| `main.py` | Command-line interface and Rekor API requests |
| `util.py` | Certificate/key loading and signature verification |
| `merkle_proof.py` | Merkle inclusion and consistency calculations |
| `artifact.md`, `artifact.bundle` | Original signed Assignment 1 artifact and bundle |
| `tests/` | Offline automated tests |
| `tests/fixtures/` | Recorded Rekor responses |
| `reports/` | Initial and final analysis results |

Do not modify or recreate the signed artifact files.

## Development

```bash
poetry install
poetry run pre-commit install
poetry run ruff format .
poetry run ruff check .
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -c pyproject.toml -r .
poetry run pytest
```

The test suite must have at least 10 tests and at least 75% total coverage.
Tests use recorded responses rather than live network requests.

To refresh the recorded responses:

```bash
poetry run python scripts/record_fixtures.py
```

Refreshing fixtures requires internet access.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution instructions and
[SECURITY.md](SECURITY.md) for reporting security problems.

## License

[MIT](LICENSE)

# Contributing

Thank you for helping improve this project.

## Proposing changes

1. Open an issue describing the change, unless one already exists.
2. Create a focused branch, such as `fix/12-input-validation`.
3. Make the change and add or update tests.
4. Open a pull request targeting `main`.
5. Link the issue in the pull request description, such as `Fixes #12`.

Do not push changes directly to `main`. It is protected and requires
pull requests and linear history. Use **Squash and merge** when accepting
a pull request.

## Development setup

Requires Python 3.10 or newer and Poetry.

```bash
poetry install
poetry run pre-commit install
```

The pre-commit hook runs TruffleHog to scan changes for secrets.
Install TruffleHog before using the hook.

Never commit real credentials, tokens, private keys, or environment files.

## Code standards

- Format Python code with Ruff.
- Keep lines within the configured 100-character limit.
- Resolve Ruff findings before submitting changes.
- Add appropriate type hints and docstrings to new functions.
- Check types with mypy and security findings with Bandit.
- Keep changes focused and preserve existing command-line behavior.

## Tests

```bash
poetry run pytest
```

Tests must run offline using recorded responses in `tests/fixtures/`.
The suite must have at least 10 tests and at least 75% total coverage.
Test both expected successes and expected failures.

Do not modify or recreate `artifact.md` or `artifact.bundle`.
Use temporary files when testing changed or invalid artifacts.

## Checks before a pull request

Run these commands and resolve any failures:

```bash
poetry run ruff format .
poetry run ruff check .
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -c pyproject.toml -r .
poetry run pytest
```

## Security reports

Follow [SECURITY.md](SECURITY.md). Do not publish vulnerability details
in a public issue.
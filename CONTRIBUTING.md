# Contributing

Thanks for your interest in contributing! This document explains how to report issues and submit changes.

## Reporting issues

- Search existing issues first to avoid duplicates.
- Open a new issue with:
  - a clear, descriptive title
  - steps to reproduce, the expected behaviour and the actual behaviour
  - a link to the relevant line(s) of code where possible (click the line number on GitHub and choose **Reference in new issue**)
- **Security vulnerabilities must not be reported as public issues.** Follow [SECURITY.md](SECURITY.md) instead.

## Development setup

```bash
git clone https://github.com/AadarshLN/SSCS-Assignment.git
cd SSCS-Assignment
poetry install
poetry run pre-commit install
```

You also need [TruffleHog](https://github.com/trufflesecurity/trufflehog) installed and on your `PATH` for the pre-commit hook.

## Submitting changes

The `main` branch is protected: all changes go through pull requests and history must stay linear.

1. Create a branch from the latest `main`:
   ```bash
   git checkout main && git pull
   git checkout -b <type>/<relevant-keywords-describing-issue>
   ```
   Use a type prefix such as `fix/`, `feat/`, `docs/`, `test/` or `refactor/`, e.g. `fix/root-hash-validation`.
2. Make focused commits with clear messages written in the imperative mood, e.g. `Fail inclusion when the signature is invalid`.
3. Make sure all checks below pass locally.
4. Push your branch and open a pull request against `main`.
   - Describe what changed and why.
   - Test results and neccessary information on reproducability 
   - Link related issues with `Closes #<number>`.
5. A code owner (see `.github/CODEOWNERS`) reviews every pull request before it is merged.
6. PRs are merged with **Rebase and merge** or **Squash and merge** to keep history linear.

## Coding style

- Code must follow [PEP 8](https://peps.python.org/pep-0008/), enforced by **ruff** (line length 88).
- Format code with `poetry run ruff format .` before committing.
- All functions must have **type hints**. mypy runs with `disallow_untyped_defs`.
- Public functions should have a docstring.
- Do not commit commented-out code, debug output files or secrets.

## Required checks (MANDATORY)

Every pull request must pass all of these with zero errors:

```bash
poetry run ruff format --check .
poetry run ruff check
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -c pyproject.toml -r .
poetry run pytest
```

## Testing requirements

- Add or update tests in `tests/` for every bug fix and new feature.
- Tests must not depend on the live Rekor service. Mock network calls (e.g. with `monkeypatch` or `unittest.mock`).
- Overall test coverage must remain at or above **75%**.

## Secrets

A pre-commit hook runs TruffleHog on every commit. If it blocks your commit:

1. Remove the secret from your changes.
2. If the secret was real, **revoke and rotate it immediately**, even if it was never pushed.
3. Never bypass the hook with `--no-verify`.

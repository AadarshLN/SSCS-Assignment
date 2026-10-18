# Python Rekor Monitor

A command-line tool that verifies entries in the [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) transparency log. It can:

- **Fetch the latest checkpoint** (tree ID, tree size, root hash) from the public Rekor instance.
- **Verify inclusion**: check that an artifact's signature is valid and that its log entry is included in the Merkle tree, by recomputing the root hash offline from the inclusion proof.
- **Verify consistency**: check that an older checkpoint is consistent with the latest one, proving the log is append-only and has not been tampered with.

Built for NYU CS-GY 9223 Software Supply Chain Security as part of Assignments

## Requirements

- Python 3.12 or newer
- [Poetry](https://python-poetry.org/) 2.x

## Installation

```bash
git clone https://github.com/AadarshLN/SSCS-Assignment.git
cd SSCS-Assignment
poetry install
```

This installs the runtime dependencies (`requests`, `cryptography`) and the development tools into a Poetry-managed virtual environment.

## Usage

All commands are run through Poetry:

```bash
poetry run python main.py [options]
```

| Option | Description |
|---|---|
| `-c`, `--checkpoint` | Print the latest checkpoint from Rekor |
| `--inclusion LOG_INDEX` | Verify inclusion of the entry at `LOG_INDEX` (requires `--artifact`) |
| `--artifact PATH` | Path to the artifact whose signature is verified |
| `--consistency` | Verify a previous checkpoint against the latest one (requires `--tree-id`, `--tree-size`, `--root-hash`) |
| `--tree-id ID` | Tree ID of the previous checkpoint |
| `--tree-size SIZE` | Tree size of the previous checkpoint |
| `--root-hash HASH` | Root hash (64 hex characters) of the previous checkpoint |
| `-d`, `--debug` | Print debug output and save the checkpoint to `checkpoint.json` |

### Examples

Get the latest checkpoint:

```bash
poetry run python main.py -c
```

Verify that an artifact was signed and logged in Rekor:

```bash
poetry run python main.py --inclusion 126574567 --artifact artifact.md
```

Verify that an older checkpoint is consistent with the current log:

```bash
poetry run python main.py --consistency \
  --tree-id 1193050959916656506 \
  --tree-size 1234567 \
  --root-hash <64-character-hex-root-hash>
```

The tool exits with status `0` when verification succeeds and a non-zero status when it fails, so it can be used in scripts and CI.

## Development

### Setup

```bash
poetry install
poetry run pre-commit install
```

The pre-commit hook runs [TruffleHog](https://github.com/trufflesecurity/trufflehog) on every commit to stop secrets from being committed. TruffleHog must be installed and on your `PATH`.

### Code quality

All tools are configured in `pyproject.toml`.

```bash
poetry run ruff format .                          # format code
poetry run ruff check                             # lint
poetry run mypy main.py merkle_proof.py util.py   # type check
poetry run bandit -c pyproject.toml -r .          # security scan (SAST)
```

### Tests

```bash
poetry run pytest
```

This runs the test suite in `tests/` and prints a coverage report. Coverage must stay at or above 75%.

## Project structure

```
main.py           CLI entry point; Rekor API calls, inclusion and consistency checks
merkle_proof.py   RFC 6962 Merkle tree hashing and proof verification
util.py           Certificate parsing and artifact signature verification
tests/            pytest test suite
pyproject.toml    Project metadata, dependencies and tool configuration
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Do not open a public issue.

## License

Released under the [MIT License](LICENSE).

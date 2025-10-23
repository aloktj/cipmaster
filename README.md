# CIP Master CLI

The CIP Master CLI is an interactive tool for validating Control and Information Protocol (CIP) configuration files, simulating IO
cycles, and communicating with target Device Control Units. The code base has been refactored to expose reusable modules for confi
guration parsing, networking helpers, and session control so that the CLI can be scripted and tested.

## Installation

The project ships with a modern `pyproject.toml` so it can be installed in editable mode together with its development dependency
set.

```bash
pip install -e .[dev]
```

This command installs the CLI entry point (`cipmaster`) along with pytest, coverage, and lint tooling used during development.

## Running the CLI

Once installed you can launch the interactive experience from anywhere on your system:

```bash
cipmaster
```

By default the CLI discovers CIP XML definitions that ship with the package. You can drop additional XML files into a `conf/` fold
er alongside your working directory and they will be picked up automatically.

## Automated Tests

The repository includes a lightweight pytest suite that exercises the configuration loader and ensures that bundled XML definition
s can be validated in a headless environment.

```bash
pytest
```

Running the tests after `pip install -e .[dev]` verifies that the editable installation works end-to-end and that the CLI can load
configuration files without prompting the user.

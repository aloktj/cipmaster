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

## Compatibility

The refactored tooling targets modern runtimes:

* Python 3.10 or newer (validated against CPython 3.12)
* Scapy 2.6.x or newer

## Running the CLI

Once installed you can launch the interactive experience from anywhere on your system:

```bash
cipmaster
```

By default the CLI discovers CIP XML definitions that ship with the package. You can drop additional XML files into a `conf/` fold
er alongside your working directory and they will be picked up automatically.


## Programmatic Usage

The refactored source tree exposes the CLI controller via `cipmaster.cli.app`.
Scripts can drive the tool without spawning a subprocess:

```python
from cipmaster.cli.app import CIPCLI, RunConfiguration, main

configuration = RunConfiguration(auto_continue=True, enable_network=False)
main(config=configuration)
```

Supporting modules are available from the `cipmaster.cip` package for direct import if you need fine-grained access to configuration, networking, or session helpers.

## Automated Tests

The repository includes a lightweight pytest suite that exercises the configuration loader and ensures that bundled XML definition
s can be validated in a headless environment.

```bash
pytest
```

Running the tests after `pip install -e .[dev]` verifies that the editable installation works end-to-end and that the CLI can load
configuration files without prompting the user.

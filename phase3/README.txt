========================================
CIP Tool – Local Development Quick Start
========================================

The CIP CLI lives in ``phase3`` and expects Python 3.10+ with a working
``scapy`` installation (raw socket support). Running the tool typically
requires administrator/root privileges because it captures and injects
EtherNet/IP packets.

Prerequisites
-------------

* Python 3.10 or newer (the refactor was validated against CPython 3.12).
* ``libpcap``/``npcap`` and the ability to open raw sockets
  (``sudo``/Administrator).
* CIP XML configuration files stored in ``phase3/conf`` – the CLI will
  prompt you to pick from the files in this directory at startup.

Environment setup
-----------------

From the repository root:

1. ``cd phase3``
2. (Optional) Create a virtual environment: ``python3 -m venv .venv``
3. Activate it (Linux/macOS ``source .venv/bin/activate``,
   Windows ``.venv\Scripts\activate``)
4. Upgrade ``pip`` inside the environment: ``python -m pip install --upgrade pip``
5. Install dependencies: ``pip install -r Requirements.txt``

Running the CLI
---------------

Execute the interactive tool from ``phase3`` (prepend ``sudo`` on Linux if
``scapy`` complains about permissions):

```
python main.py
```

On startup the CLI will:

1. Display a banner and prompt you to continue.
2. Offer the list of CIP XML files found under ``conf/`` for validation and
   dynamic packet-class construction.
3. Optionally run the multicast and reachability checks (controlled by the
   ``ENABLE_NETWORK`` flag near the top of ``main.py``).
4. Launch the interactive command loop for session control once the
   configuration and network checks pass.

Logs and artifacts
------------------

* Logs are written to ``phase3/log/app.log`` (created automatically).
* Temporary packet classes and validation results are in memory only; rerun the
  CLI to refresh them after editing a configuration file.

Deactivating the virtual environment
------------------------------------

When you are finished, exit the virtual environment with ``deactivate``.

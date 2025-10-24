"""Command-line interface entry points for the CIP master tool."""

from __future__ import annotations

import click

from .app import CIPCLI, RunConfiguration, main as _app_main


@click.command()
@click.option("--auto-continue", type=bool, default=None, help="Skip the confirmation prompt when starting the CLI.")
@click.option("--cip-filename", type=str, default=None, help="CIP configuration file to load on start.")
@click.option("--target-ip", type=str, default=None, help="Target IP address for communication tests.")
@click.option("--multicast-address", type=str, default=None, help="Multicast group address for join tests.")
@click.option(
    "--enable-network",
    type=bool,
    default=None,
    help="Override automatic network configuration enablement.",
)
def main(
    auto_continue: bool | None,
    cip_filename: str | None,
    target_ip: str | None,
    multicast_address: str | None,
    enable_network: bool | None,
) -> None:
    """Invoke the interactive CIP master CLI."""

    configuration = RunConfiguration(
        auto_continue=auto_continue,
        cip_filename=cip_filename,
        target_ip=target_ip,
        multicast_address=multicast_address,
        enable_network=enable_network,
    )
    _app_main(config=configuration)


__all__ = ["CIPCLI", "RunConfiguration", "main"]

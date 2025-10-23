"""Tests for multicast route discovery utilities."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cip import network


class StubPlatform(network.PlatformService):
    def __init__(self, name: str) -> None:
        self._name = name

    def system(self) -> str:  # type: ignore[override]
        return self._name


class RecordingSubprocess(network.SubprocessService):
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.commands: list[list[str]] = []

    def run(self, command, **_) -> SimpleNamespace:  # type: ignore[override]
        self.commands.append(list(command))
        return SimpleNamespace(stdout=self.stdout)


WINDOWS_ROUTE_OUTPUT = """
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.0.1   192.168.0.100     25
        224.0.0.0        240.0.0.0         On-link    192.168.0.100    256
        239.255.255.250  255.255.255.255    On-link    192.168.0.100    256
===========================================================================
"""


LINUX_ROUTE_OUTPUT = """
default via 192.168.0.1 dev eth0 proto dhcp metric 100
224.0.0.0/4 dev eth0 scope link
239.0.0.0/8 dev eth0 scope link
"""


LINUX_MULTICAST_KEYWORD_OUTPUT = """
multicast 239.192.0.0 dev eth0 scope link src 172.16.5.16
multicast 239.192.1.2 dev eth0 scope link src 172.16.5.16
multicast 224.0.0.0 dev eth0 scope link src 172.16.5.16
"""


DARWIN_ROUTE_OUTPUT = """
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
224.0.0/4          link#4             UmCS            en0
239.255.0/16       link#4             UmcW            en0
"""


@pytest.mark.parametrize(
    "platform_name, output, expected_command, expected_route",
    [
        ("Windows", WINDOWS_ROUTE_OUTPUT, ["route", "print"], "224.0.0.0/4"),
        (
            "Linux",
            LINUX_ROUTE_OUTPUT,
            ["ip", "route", "show", "table", "all"],
            "224.0.0.0/4",
        ),
        ("Darwin", DARWIN_ROUTE_OUTPUT, ["netstat", "-rn"], "224.0.0.0/4"),
    ],
)
def test_get_multicast_route_cross_platform(
    platform_name, output, expected_command, expected_route
):
    subprocess_service = RecordingSubprocess(output)
    route = network.get_multicast_route(
        platform_service=StubPlatform(platform_name),
        subprocess_service=subprocess_service,
    )

    assert subprocess_service.commands[0] == expected_command
    assert route == expected_route


def test_get_multicast_route_respects_smaller_subnet():
    subprocess_service = RecordingSubprocess("239.192.0.0/16 dev eth0 scope link")
    route = network.get_multicast_route(
        platform_service=StubPlatform("Linux"),
        subprocess_service=subprocess_service,
    )

    assert route == "239.192.0.0/16"


def test_check_multicast_support_accepts_valid_address():
    supported, route_exists, route = network.check_multicast_support(
        "239.192.1.2", route="224.0.0.0/4"
    )

    assert supported is True
    assert route_exists is True
    assert route == "224.0.0.0/4"


@pytest.mark.parametrize(
    "output, expected_route",
    [
        (
            "multicast 239.192.0.0 dev eth0 scope link src 172.16.5.16",
            "239.192.0.0/16",
        ),
        (
            "multicast 239.192.1.2 dev eth0 scope link src 172.16.5.16",
            "239.192.1.2/32",
        ),
        (
            "multicast 224.0.0.0 dev eth0 scope link src 172.16.5.16",
            "224.0.0.0/4",
        ),
        (LINUX_MULTICAST_KEYWORD_OUTPUT, "239.192.0.0/16"),
    ],
)
def test_get_multicast_route_handles_keyword_routes(output, expected_route):
    subprocess_service = RecordingSubprocess(output)
    route = network.get_multicast_route(
        platform_service=StubPlatform("Linux"),
        subprocess_service=subprocess_service,
    )

    assert route == expected_route

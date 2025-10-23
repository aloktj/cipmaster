"""Networking helpers for CIP communication checks."""

from __future__ import annotations

import ipaddress
import logging
import platform
import subprocess
from dataclasses import dataclass
from typing import Optional, Sequence, Union

logger = logging.getLogger(__name__)


@dataclass
class NetworkCheckResult:
    """Result of running the network connectivity checks."""

    reachable: bool
    multicast_supported: bool
    route_exists: bool
    route: Optional[str] = None


CommandType = Union[str, Sequence[str]]


class PlatformService:
    """Abstraction over :func:`platform.system` for testability."""

    def system(self) -> str:
        return platform.system()


class SubprocessService:
    """Wrapper around :mod:`subprocess` calls used by the network helpers."""

    def call(self, command: CommandType) -> int:
        if isinstance(command, str):
            return subprocess.call(command, shell=True)
        return subprocess.call(command)

    def run(
        self,
        command: Sequence[str],
        *,
        capture_output: bool = True,
        text: bool = True,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=capture_output,
            text=text,
            check=check,
        )


def _default_ping_command(
    ip_address: str,
    *,
    platform_service: Optional[PlatformService] = None,
) -> Sequence[str]:
    service = platform_service or PlatformService()
    if service.system() == "Windows":
        return ["ping", "-n", "1", ip_address]
    return ["ping", "-c", "1", ip_address]


def communicate_with_target(
    ip_address: str,
    ping_command: Optional[CommandType] = None,
    *,
    subprocess_service: Optional[SubprocessService] = None,
    platform_service: Optional[PlatformService] = None,
) -> bool:
    """Return ``True`` if the target responds to a ping command."""

    command: CommandType = ping_command or _default_ping_command(
        ip_address, platform_service=platform_service
    )
    runner = subprocess_service or SubprocessService()
    try:
        result = runner.call(command)
    except OSError as exc:
        logger.warning("Ping command failed: %s", exc)
        return False
    return result == 0


def get_multicast_route(
    *,
    platform_service: Optional[PlatformService] = None,
    subprocess_service: Optional[SubprocessService] = None,
) -> Optional[str]:
    """Return the multicast route configured on the host, if any."""

    platform_service = platform_service or PlatformService()
    subprocess_service = subprocess_service or SubprocessService()
    try:
        system = platform_service.system()
        if system == "Windows":
            result = subprocess_service.run(["route", "print"])
        elif system in {"Linux", "Darwin"}:
            result = subprocess_service.run(["ip", "route"])
        else:
            logger.warning("Unsupported operating system for multicast route lookup")
            return None
    except (OSError, subprocess.CalledProcessError) as exc:
        logger.warning("Failed to obtain multicast route: %s", exc)
        return None

    for line in result.stdout.splitlines():
        if "224.0.0.0/4" in line:
            return "224.0.0.0/4"
    return None


def check_multicast_support(
    multicast_address: str,
    route: Optional[str] = None,
    *,
    platform_service: Optional[PlatformService] = None,
    subprocess_service: Optional[SubprocessService] = None,
) -> tuple[bool, bool, Optional[str]]:
    """Check whether the multicast address is reachable via the host route."""

    try:
        user_ip = ipaddress.IPv4Address(multicast_address)
    except ipaddress.AddressValueError as exc:
        logger.warning("Invalid multicast address provided: %s", exc)
        return False, False, route

    route = (
        route
        if route is not None
        else get_multicast_route(
            platform_service=platform_service,
            subprocess_service=subprocess_service,
        )
    )
    route_exists = route is not None
    if not route_exists:
        return False, False, route

    try:
        platform_route = ipaddress.IPv4Network(route, strict=False)
    except ValueError as exc:
        logger.warning("Invalid multicast route discovered: %s", exc)
        return False, True, route

    multicast_supported = user_ip in platform_route
    return multicast_supported, True, route


def config_network(
    ip_address: str,
    multicast_address: str,
    *,
    ping_command: Optional[CommandType] = None,
    platform_service: Optional[PlatformService] = None,
    subprocess_service: Optional[SubprocessService] = None,
) -> NetworkCheckResult:
    """Run network connectivity checks and report the results."""

    reachable = communicate_with_target(
        ip_address,
        ping_command=ping_command,
        subprocess_service=subprocess_service,
        platform_service=platform_service,
    )
    multicast_supported, route_exists, route = check_multicast_support(
        multicast_address,
        platform_service=platform_service,
        subprocess_service=subprocess_service,
    )
    return NetworkCheckResult(
        reachable=reachable,
        multicast_supported=multicast_supported,
        route_exists=route_exists,
        route=route,
    )


__all__ = [
    "NetworkCheckResult",
    "communicate_with_target",
    "config_network",
    "check_multicast_support",
    "get_multicast_route",
    "PlatformService",
    "SubprocessService",
]

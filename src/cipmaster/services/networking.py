"""Service wrappers for networking utilities used by the CLI."""

from __future__ import annotations

from typing import Optional

from cipmaster.cip import network as cip_network


class NetworkingService:
    """Thin adapter around :mod:`cipmaster.cip.network`."""

    def configure_network(
        self,
        ip_address: str,
        multicast_address: str,
        *,
        ping_command: Optional[cip_network.CommandType] = None,
        platform_service: Optional[cip_network.PlatformService] = None,
        subprocess_service: Optional[cip_network.SubprocessService] = None,
    ):
        return cip_network.config_network(
            ip_address,
            multicast_address,
            ping_command=ping_command,
            platform_service=platform_service,
            subprocess_service=subprocess_service,
        )

    def communicate_with_target(
        self,
        ip_address: str,
        ping_command: Optional[cip_network.CommandType] = None,
        *,
        platform_service: Optional[cip_network.PlatformService] = None,
        subprocess_service: Optional[cip_network.SubprocessService] = None,
    ) -> bool:
        return cip_network.communicate_with_target(
            ip_address,
            ping_command=ping_command,
            platform_service=platform_service,
            subprocess_service=subprocess_service,
        )

    def get_multicast_route(self, *, platform_service=None, subprocess_service=None):
        return cip_network.get_multicast_route(
            platform_service=platform_service,
            subprocess_service=subprocess_service,
        )

    def __getattr__(self, item):
        return getattr(cip_network, item)


__all__ = ["NetworkingService"]

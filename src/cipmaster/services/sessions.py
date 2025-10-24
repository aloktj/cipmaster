"""Session-related helpers used by the CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Type

from cipmaster.cip import session as cip_session


@dataclass
class CalculatedConnectionParameters:
    """Result of deriving session connection parameters from assemblies."""

    ot_param: Optional[int]
    to_param: Optional[int]

    @property
    def is_valid(self) -> bool:
        return self.ot_param is not None and self.to_param is not None

    def to_connection_parameters(self, factory: Type[cip_session.ConnectionParameters]) -> cip_session.ConnectionParameters:
        if not self.is_valid:
            raise ValueError("Cannot create ConnectionParameters without both OT and TO values.")
        return factory(ot_param=self.ot_param, to_param=self.to_param)


class SessionService:
    """Adapter around :mod:`cipmaster.cip.session`."""

    def create_session(self, *args, **kwargs):
        return cip_session.CIPSession(*args, **kwargs)

    def calculate_connection_params(self, ot_assembly, to_assembly) -> CalculatedConnectionParameters:
        def _extract_size(node) -> Optional[int]:
            if node is None:
                return None
            try:
                size_text = getattr(node, "attrib", {}).get("size")
            except AttributeError:
                size_text = None
            if size_text is None:
                return None
            try:
                return int(size_text)
            except (TypeError, ValueError):
                return None

        ot_size = _extract_size(ot_assembly)
        to_size = _extract_size(to_assembly)

        ot_param = 0x4800 | ((ot_size // 8) + 6) if ot_size is not None else None
        to_param = 0x2800 | ((to_size // 8) + 6) if to_size is not None else None

        return CalculatedConnectionParameters(ot_param=ot_param, to_param=to_param)

    def start_session(
        self,
        session: cip_session.CIPSession,
        *,
        ip_address: str,
        multicast_address: str,
        connection_params: cip_session.ConnectionParameters,
        to_packet_class,
        ot_packet,
        heartbeat_callback: Callable[[str, int], None],
        update_to_packet: Callable[[object], None],
    ) -> None:
        session.start(
            ip_address=ip_address,
            multicast_address=multicast_address,
            connection_params=connection_params,
            to_packet_class=to_packet_class,
            ot_packet=ot_packet,
            heartbeat_callback=heartbeat_callback,
            update_to_packet=update_to_packet,
        )

    def stop_session(self, session: cip_session.CIPSession) -> None:
        session.stop()

    def __getattr__(self, item):
        return getattr(cip_session, item)


__all__ = ["SessionService", "CalculatedConnectionParameters"]

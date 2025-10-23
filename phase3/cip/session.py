"""Session management helpers for CIP IO communication."""

from __future__ import annotations

import calendar
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Type

from scapy import all as scapy_all

from thirdparty.scapy_cip_enip.tgv2020 import Client

logger = logging.getLogger(__name__)

HeartbeatCallback = Callable[[str, int], None]
UpdatePacketCallback = Callable[[scapy_all.Packet], None]


@dataclass
class ConnectionParameters:
    ot_param: int
    to_param: int


class CIPSession:
    """Manage the lifecycle of a CIP IO communication session."""

    def __init__(
        self,
        *,
        client_factory: Type[Client] = Client,
        lock: Optional[threading.Lock] = None,
        debug_cip_frames: bool = False,
    ) -> None:
        self._client_factory = client_factory
        self._lock = lock or threading.Lock()
        self._debug_cip_frames = debug_cip_frames
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._client: Optional[Client] = None
        self.error_occurred: bool = False

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(
        self,
        *,
        ip_address: str,
        multicast_address: str,
        connection_params: ConnectionParameters,
        to_packet_class: Type[scapy_all.Packet],
        ot_packet: scapy_all.Packet,
        heartbeat_callback: HeartbeatCallback,
        update_to_packet: UpdatePacketCallback,
    ) -> None:
        if self.running:
            raise RuntimeError("CIP session already running")

        self._stop_event.clear()
        self.error_occurred = False

        def _run() -> None:
            try:
                self._client = self._client_factory(IPAddr=ip_address, MulticastGroupIPaddr=multicast_address)
                self._client.ot_connection_param = connection_params.ot_param
                self._client.to_connection_param = connection_params.to_param

                if not self._client.connected:
                    logger.warning("Unable to establish CIP session")
                    self.error_occurred = True
                    return

                if not self._client.forward_open():
                    logger.warning("Forward open request failed")
                    self.error_occurred = True
                    return

                self.error_occurred = self.manage_io_communication(
                    self._client,
                    to_packet_class=to_packet_class,
                    ot_packet=ot_packet,
                    heartbeat_callback=heartbeat_callback,
                    update_to_packet=update_to_packet,
                )

                if not self.error_occurred:
                    try:
                        self._client.forward_close()
                    except Exception:  # pragma: no cover - best effort cleanup
                        logger.exception("Failed to close CIP session cleanly")
            except Exception:  # pragma: no cover - defensive
                logger.exception("Unexpected error while running CIP session")
                self.error_occurred = True
            finally:
                if self._client is not None:
                    try:
                        self._client.close()
                    except Exception:
                        logger.exception("Failed to close CIP client")

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._client is not None:
            try:
                if self._client.connected:
                    self._client.forward_close()
            except Exception:
                logger.exception("Failed to forward close CIP session during stop")
            finally:
                try:
                    self._client.close()
                except Exception:
                    logger.exception("Failed to close CIP client during stop")
        if self._thread is not None:
            self._thread.join(timeout=1)

    def manage_io_communication(
        self,
        client: Client,
        *,
        to_packet_class: Type[scapy_all.Packet],
        ot_packet: scapy_all.Packet,
        heartbeat_callback: HeartbeatCallback,
        update_to_packet: UpdatePacketCallback,
    ) -> bool:
        """Manage the cyclic CIP IO communication loop."""

        mpu_alive = 0
        cip_app_counter = 65500
        error_occurred = False

        while not error_occurred and not self._stop_event.is_set():
            pkg_cip_io = client.recv_UDP_ENIP_CIP_IO(self._debug_cip_frames, 0.5)

            if pkg_cip_io is None:
                logger.debug("No CIP IO packet received; retrying")
                continue

            try:
                with self._lock:
                    to_packet = to_packet_class(pkg_cip_io.payload.load)
                update_to_packet(to_packet)
            except Exception:
                logger.exception("Unable to parse TO packet from CIP IO payload")
                error_occurred = True
                break

            if mpu_alive >= 255:
                mpu_alive = 0
            else:
                mpu_alive += 1

            try:
                heartbeat_callback("MPU_CTCMSAlive", mpu_alive)
            except Exception:
                logger.exception("Heartbeat callback failed")
                error_occurred = True
                break

            ot_packet.MPU_CDateTimeSec = calendar.timegm(time.gmtime())

            try:
                client.send_UDP_ENIP_CIP_IO(
                    CIP_Sequence_Count=cip_app_counter,
                    Header=1,
                    AppData=ot_packet,
                )
            except Exception:
                logger.exception("Failed to send CIP IO packet")
                error_occurred = True
                break

            if cip_app_counter < 65535:
                cip_app_counter += 1
            else:
                cip_app_counter = 0

        return error_occurred


__all__ = [
    "CIPSession",
    "ConnectionParameters",
]

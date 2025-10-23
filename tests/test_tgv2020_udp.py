"""Tests for UDP CIP IO reception helpers in the TGV client."""

from __future__ import annotations

import socket

from scapy import all as scapy_all

from thirdparty.scapy_cip_enip import tgv2020
from thirdparty.scapy_cip_enip.enip_udp import (
    CIP_IO,
    ENIP_UDP,
    ENIP_UDP_Item,
    ENIP_UDP_SequencedAddress,
)


class _FakeSocket:
    def __init__(self, frames: list[bytes]) -> None:
        self._frames = frames
        self.timeout = 0.0

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def recvfrom(self, size: int):  # type: ignore[override]
        if not self._frames:
            raise socket.timeout()
        return self._frames.pop(0), ("127.0.0.1", 2222)


def _build_enip_frame(app_packet: scapy_all.Packet, *, extra_item: bool = False) -> bytes:
    items = [
        ENIP_UDP_Item(type_id=0x8002)
        / ENIP_UDP_SequencedAddress(connection_id=0x1111, sequence=1)
    ]
    if extra_item:
        items.append(
            ENIP_UDP_Item(type_id=0x8002)
            / ENIP_UDP_SequencedAddress(connection_id=0x2222, sequence=2)
        )
    items.append(
        ENIP_UDP_Item(type_id=0x00B1)
        / (CIP_IO(CIP_Sequence_Count=42, Header=1) / app_packet)
    )
    return bytes(ENIP_UDP(items=items))


def _client_with_frames(frames: list[bytes]) -> tgv2020.Client:
    original_flag = tgv2020.NO_NETWORK
    tgv2020.NO_NETWORK = True
    try:
        client = tgv2020.Client()
    finally:
        tgv2020.NO_NETWORK = original_flag
    client.MulticastSock = _FakeSocket(frames)
    return client


def test_recv_udp_enip_cip_io_returns_packet_with_payload():
    payload = tgv2020.AS_DCUi_MPU_DATA(BCHi_IDevIsAlive=5)
    frame = _build_enip_frame(payload)
    client = _client_with_frames([frame])

    packet = client.recv_UDP_ENIP_CIP_IO(False, 0.5)

    assert isinstance(packet, CIP_IO)
    assert packet.CIP_Sequence_Count == 42
    assert bytes(packet.payload) == bytes(payload)


def test_recv_udp_enip_cip_io_ignores_additional_items():
    payload = tgv2020.AS_DCUi_MPU_DATA(BCHi_IDevIsAlive=7)
    frame = _build_enip_frame(payload, extra_item=True)
    client = _client_with_frames([frame])

    packet = client.recv_UDP_ENIP_CIP_IO(False, 0.5)

    assert isinstance(packet, CIP_IO)
    assert bytes(packet.payload) == bytes(payload)


def test_recv_udp_enip_cip_io_returns_none_without_connected_item():
    extra_only = bytes(
        ENIP_UDP(
            items=[
                ENIP_UDP_Item(type_id=0x8002)
                / ENIP_UDP_SequencedAddress(connection_id=0x3333, sequence=3)
            ]
        )
    )
    client = _client_with_frames([extra_only])

    assert client.recv_UDP_ENIP_CIP_IO(False, 0.5) is None

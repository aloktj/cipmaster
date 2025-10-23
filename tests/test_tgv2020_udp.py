"""Tests for UDP CIP IO reception helpers in the TGV client."""

from __future__ import annotations

import socket
import struct

import pytest

from scapy import all as scapy_all

from thirdparty.scapy_cip_enip import tgv2020
from thirdparty.scapy_cip_enip import enip_tcp
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


def _register_session_response() -> bytes:
    return bytes(
        enip_tcp.ENIP_TCP(command_id=0x0065, session=0x1234)
        / enip_tcp.ENIP_RegisterSession()
    )


class _FakeTcpSocket:
    def __init__(self, *, local_ip: str | None) -> None:
        self._local_ip = local_ip
        self.sent: list[bytes] = []

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        return _register_session_response()

    def getsockname(self) -> tuple[str, int]:
        if self._local_ip is None:
            raise OSError("no interface")
        return self._local_ip, 40000

    def close(self) -> None:  # pragma: no cover - not used in tests
        pass


class _FakeUdpSocket:
    def __init__(self) -> None:
        self.options: list[tuple[int, int, bytes]] = []
        self.bound: tuple[str, int] | None = None
        self.connected: tuple[str, int] | None = None

    def setsockopt(self, level: int, option: int, value) -> None:
        if isinstance(value, memoryview):  # pragma: no cover - defensive
            value = value.tobytes()
        self.options.append((level, option, value))

    def bind(self, address: tuple[str, int]) -> None:
        self.bound = address

    def connect(self, address: tuple[str, int]) -> None:
        self.connected = address

    def close(self) -> None:  # pragma: no cover - not used in tests
        pass


@pytest.fixture
def _patched_sockets(monkeypatch):
    sockets: list[_FakeUdpSocket] = []

    def fake_socket(family: int, type_: int) -> _FakeUdpSocket:
        assert family == socket.AF_INET
        assert type_ == socket.SOCK_DGRAM
        sock = _FakeUdpSocket()
        sockets.append(sock)
        return sock

    monkeypatch.setattr(tgv2020.socket, "socket", fake_socket)
    return sockets


def test_client_joins_multicast_on_detected_interface(monkeypatch, _patched_sockets):
    tcp_socket = _FakeTcpSocket(local_ip="172.16.0.10")
    monkeypatch.setattr(tgv2020.socket, "create_connection", lambda addr: tcp_socket)

    client = tgv2020.Client(
        IPAddr="172.16.0.230",
        MulticastGroupIPaddr="239.192.29.163",
    )

    multicast_sock = _patched_sockets[0]
    assert multicast_sock.bound == ("", 2222)

    membership_calls = []
    for level, option, value in multicast_sock.options:
        if level == socket.IPPROTO_IP and option == socket.IP_ADD_MEMBERSHIP:
            assert isinstance(value, (bytes, bytearray))
            membership_calls.append(bytes(value))
    assert membership_calls == [
        struct.pack(
            "4s4s",
            socket.inet_aton("239.192.29.163"),
            socket.inet_aton("172.16.0.10"),
        )
    ]

    client.close()


def test_client_falls_back_to_any_when_interface_unknown(monkeypatch, _patched_sockets):
    tcp_socket = _FakeTcpSocket(local_ip=None)
    monkeypatch.setattr(tgv2020.socket, "create_connection", lambda addr: tcp_socket)

    client = tgv2020.Client(
        IPAddr="172.16.0.230",
        MulticastGroupIPaddr="239.192.29.163",
    )

    multicast_sock = _patched_sockets[0]
    membership_calls = []
    for level, option, value in multicast_sock.options:
        if level == socket.IPPROTO_IP and option == socket.IP_ADD_MEMBERSHIP:
            assert isinstance(value, (bytes, bytearray))
            membership_calls.append(bytes(value))
    assert membership_calls[-1] == struct.pack(
        "4sL", socket.inet_aton("239.192.29.163"), socket.INADDR_ANY
    )

    client.close()

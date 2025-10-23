"""Tests for CIP session management helpers."""

from __future__ import annotations

import calendar
import time

from scapy import all as scapy_all

from cip.session import CIPSession


class DummyToPacket(scapy_all.Packet):
    name = "DummyToPacket"
    fields_desc = [scapy_all.ByteField("value", 0)]


class DummyOtPacket(scapy_all.Packet):
    name = "DummyOtPacket"
    fields_desc = [scapy_all.IntField("MPU_CDateTimeSec", 0)]


class _FakePayload:
    def __init__(self, data: bytes) -> None:
        self.load = data

    def __bytes__(self) -> bytes:
        return self.load


class _FakeCIPIOPacket:
    def __init__(self, payload) -> None:  # type: ignore[no-untyped-def]
        self.payload = payload


class _FakeClient:
    def __init__(self) -> None:
        self._recv_calls = 0
        self.sent = []

    def recv_UDP_ENIP_CIP_IO(self, debug: bool, timeout: float):
        self._recv_calls += 1
        if self._recv_calls == 1:
            return None
        return _FakeCIPIOPacket(_FakePayload(b"\x07"))

    def send_UDP_ENIP_CIP_IO(self, *, CIP_Sequence_Count: int, Header: int, AppData: scapy_all.Packet) -> None:
        self.sent.append((CIP_Sequence_Count, Header, AppData))


def test_manage_io_communication_ignores_transient_timeouts():
    session = CIPSession()
    client = _FakeClient()
    updates = []
    heartbeats = []

    def update_to_packet(pkt: DummyToPacket) -> None:
        updates.append(pkt.value)
        session._stop_event.set()  # type: ignore[attr-defined]

    def heartbeat_callback(name: str, value: int) -> None:
        heartbeats.append((name, value))

    result = session.manage_io_communication(
        client,
        to_packet_class=DummyToPacket,
        ot_packet=DummyOtPacket(),
        heartbeat_callback=heartbeat_callback,
        update_to_packet=update_to_packet,
    )

    assert result is False
    assert updates == [7]
    assert heartbeats == [("MPU_CTCMSAlive", 1)]
    assert len(client.sent) == 1
    seq_count, header, app_data = client.sent[0]
    assert seq_count == 65500
    assert header == 1
    assert isinstance(app_data, DummyOtPacket)
    assert isinstance(app_data.MPU_CDateTimeSec, int)
    now = calendar.timegm(time.gmtime())
    assert now - 5 <= app_data.MPU_CDateTimeSec <= now + 5


def test_manage_io_communication_accepts_scapy_payload():
    session = CIPSession()

    class _ClientWithPacket(_FakeClient):
        def recv_UDP_ENIP_CIP_IO(self, debug: bool, timeout: float):  # type: ignore[override]
            self._recv_calls += 1
            return _FakeCIPIOPacket(DummyToPacket(value=9))

    client = _ClientWithPacket()
    updates = []

    def update_to_packet(pkt: DummyToPacket) -> None:
        updates.append(pkt.value)
        session._stop_event.set()  # type: ignore[attr-defined]

    session.manage_io_communication(
        client,
        to_packet_class=DummyToPacket,
        ot_packet=DummyOtPacket(),
        heartbeat_callback=lambda *_: None,
        update_to_packet=update_to_packet,
    )

    assert updates == [9]

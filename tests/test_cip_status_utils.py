from types import SimpleNamespace

from thirdparty.scapy_cip_enip import tgv2020, utils
from thirdparty.scapy_cip_enip.cip import CIP_RespForwardOpen


def test_cip_status_details_handles_missing_status():
    code, status = utils.cip_status_details(SimpleNamespace(status=[]))

    assert code == 0
    assert status is None


def test_cip_status_details_returns_existing_status_object():
    expected = SimpleNamespace(status=6)

    code, status = utils.cip_status_details(SimpleNamespace(status=[expected]))

    assert code == 6
    assert status is expected


def test_forward_open_tolerates_missing_status(monkeypatch):
    monkeypatch.setattr(tgv2020, "NO_NETWORK", True, raising=False)

    client = tgv2020.Client()
    client.Sock = object()
    client.ot_connection_param = 0x1234
    client.to_connection_param = 0x5678
    client.send_rr_cip = lambda _: None

    payload = CIP_RespForwardOpen(
        OT_network_connection_id=111,
        TO_network_connection_id=222,
        connection_serial_number=0,
        vendor_id=0,
        originator_serial_number=0,
        OT_api=0,
        TO_api=0,
        application_reply_size=0,
    )

    class DummyResponse:
        def __getitem__(self, _):
            return SimpleNamespace(status=[], payload=payload)

    client.recv_enippkt = lambda: DummyResponse()

    assert client.forward_open() is True
    assert client.enip_connection_id_OT == 111
    assert client.enip_connection_id_TO == 222

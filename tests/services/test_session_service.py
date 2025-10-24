from xml.etree.ElementTree import Element

import pytest

from cipmaster.cip.session import ConnectionParameters
from cipmaster.services.sessions import SessionService


def test_calculate_connection_params_success():
    service = SessionService()
    ot = Element("Assembly", attrib={"size": "16"})
    to = Element("Assembly", attrib={"size": "32"})

    result = service.calculate_connection_params(ot, to)

    expected_ot = 0x4800 | ((16 // 8) + 6)
    expected_to = 0x2800 | ((32 // 8) + 6)

    assert result.ot_param == expected_ot
    assert result.to_param == expected_to
    assert result.is_valid

    params = result.to_connection_parameters(ConnectionParameters)
    assert params.ot_param == expected_ot
    assert params.to_param == expected_to


def test_calculate_connection_params_missing_values():
    service = SessionService()
    ot = Element("Assembly", attrib={})

    result = service.calculate_connection_params(ot, None)

    assert not result.is_valid
    assert result.ot_param is None or result.to_param is None

    with pytest.raises(ValueError):
        result.to_connection_parameters(ConnectionParameters)


def test_session_start_and_stop_helpers():
    service = SessionService()

    class DummySession:
        def __init__(self):
            self.started = False
            self.stopped = False
            self.kwargs = None

        def start(self, **kwargs):
            self.started = True
            self.kwargs = kwargs

        def stop(self):
            self.stopped = True

    session = DummySession()
    params = ConnectionParameters(ot_param=1, to_param=2)

    service.start_session(
        session,
        ip_address="10.0.0.1",
        multicast_address="239.1.1.1",
        connection_params=params,
        to_packet_class=object,
        ot_packet="packet",
        heartbeat_callback=lambda *_args, **_kwargs: None,
        update_to_packet=lambda *_args, **_kwargs: None,
    )

    assert session.started
    assert session.kwargs["ip_address"] == "10.0.0.1"
    assert session.kwargs["connection_params"] is params

    service.stop_session(session)
    assert session.stopped

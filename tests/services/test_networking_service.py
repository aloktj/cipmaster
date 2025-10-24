from cipmaster.cip.network import NetworkCheckResult
from cipmaster.services.networking import NetworkConfigurationSummary, NetworkingService


def test_run_configuration_formats_table():
    service = NetworkingService()
    result = NetworkCheckResult(reachable=True, multicast_supported=False, route_exists=True, route="0.0.0.0/0")

    captured = {}

    def fake_configurator(ip_address, multicast_address, **kwargs):
        captured["ip"] = ip_address
        captured["multicast"] = multicast_address
        captured["kwargs"] = kwargs
        return result

    summary = service.run_configuration(
        "10.0.0.1",
        "239.1.1.1",
        configurator=fake_configurator,
        ping_command="ping",
    )

    assert isinstance(summary, NetworkConfigurationSummary)
    assert summary.result is result
    assert summary.table[1][1] == "OK"
    assert summary.table[2][1] == "FAILED"
    assert summary.table[3][1] == "OK"
    assert captured["ip"] == "10.0.0.1"
    assert captured["multicast"] == "239.1.1.1"
    assert captured["kwargs"]["ping_command"] == "ping"

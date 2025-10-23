from cip import config as cip_config


def test_example_config_available():
    files = cip_config.get_available_config_files()
    assert files, "expected at least one packaged CIP configuration"
    assert any(name.endswith('.xml') for name in files)

from typing import Any

from cip import config as cip_config
from main import CLI


class DummyUI:
    def prompt(self, text: str, **_: Any) -> Any:
        raise AssertionError(f"Unexpected prompt: {text}")

    def confirm(self, text: str, **_: Any) -> bool:
        raise AssertionError(f"Unexpected confirmation: {text}")

    def echo(self, message: str = "", *, nl: bool = True) -> None:  # pragma: no cover - display helper
        pass

    def write(self, *args: Any, sep: str = " ", end: str = "\n") -> None:  # pragma: no cover - display helper
        pass


def test_cli_loads_selected_configuration(monkeypatch):
    files = cip_config.get_available_config_files()
    name, _ = next(iter(files.items()))

    cli = CLI(ui=DummyUI())
    cli.cip_test_flag = True

    assert cli.cip_config(preselected_filename=name)
    assert cli.cip_config_selected == name
    assert cli.overall_cip_valid is True

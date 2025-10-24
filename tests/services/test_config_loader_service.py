from pathlib import Path

from cipmaster.services import config_loader
from cipmaster.services.config_loader import ConfigLoaderService, ConfigOptions


def test_discover_configurations(monkeypatch):
    service = ConfigLoaderService()
    mapping = {"b.xml": Path("b.xml"), "a.xml": Path("a.xml")}
    monkeypatch.setattr(
        config_loader.cip_config,
        "get_available_config_files",
        lambda: mapping,
    )

    options = service.discover_configurations()

    assert options.names == ["a.xml", "b.xml"]
    assert options.mapping == mapping
    assert options.count == 2
    assert options.last == "b.xml"


def test_select_configuration_prefers_preselected():
    service = ConfigLoaderService()
    options = ConfigOptions(mapping={}, names=["one.xml", "two.xml"])

    result = service.select_configuration(options, attempts=0, preselected="two.xml")

    assert result.filename == "two.xml"
    assert not result.prompted


def test_select_configuration_prompts_when_needed():
    service = ConfigLoaderService()
    options = ConfigOptions(mapping={}, names=["one.xml", "two.xml"])

    prompts = []

    def prompt(message, **_):
        prompts.append(message)
        return "chosen.xml"

    result = service.select_configuration(options, attempts=0, prompt=prompt)

    assert result.filename == "chosen.xml"
    assert result.prompted
    assert prompts == ["CIP Configuration Filename"]


def test_select_configuration_respects_confirmation():
    service = ConfigLoaderService()
    options = ConfigOptions(mapping={}, names=["one.xml", "two.xml"])

    result = service.select_configuration(
        options,
        attempts=1,
        current_selection="current.xml",
        confirm=lambda *_args, **_kwargs: False,
    )

    assert result.filename == "current.xml"
    assert not result.prompted


def test_select_configuration_prompts_after_confirmation():
    service = ConfigLoaderService()
    options = ConfigOptions(mapping={}, names=["one.xml", "two.xml"])

    result = service.select_configuration(
        options,
        attempts=2,
        current_selection="current.xml",
        confirm=lambda *_args, **_kwargs: True,
        prompt=lambda *_args, **_kwargs: "new.xml",
    )

    assert result.filename == "new.xml"
    assert result.prompted


def test_resolve_selection(monkeypatch):
    service = ConfigLoaderService()
    mapping = {"conf.xml": Path("/tmp/conf.xml")}
    options = ConfigOptions(mapping=mapping, names=["conf.xml"])

    monkeypatch.setattr(
        config_loader.cip_config,
        "resolve_config_path",
        lambda filename, available=None: available[filename],
    )

    resolved = service.resolve_selection("conf.xml", options)

    assert resolved == mapping["conf.xml"]


def test_validate_selection(monkeypatch):
    service = ConfigLoaderService()
    captured = {}

    def fake_validate(path):
        captured["path"] = path
        return "ok"

    monkeypatch.setattr(config_loader.cip_config, "validate_cip_config", fake_validate)

    result = service.validate_selection(Path("/path/to/conf.xml"))

    assert result == "ok"
    assert captured["path"].endswith("conf.xml")

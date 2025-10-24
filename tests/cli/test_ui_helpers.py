import io

from cipmaster.cli import ui_helpers
from cipmaster.cli.ui_helpers import CLIUIHelpers


def test_render_banner(monkeypatch):
    helper = CLIUIHelpers()

    monkeypatch.setattr(ui_helpers.pyfiglet, "figlet_format", lambda text, font=None: "BANNER")
    monkeypatch.setattr(ui_helpers, "colored", lambda text, color=None: f"[{text}]")
    monkeypatch.setattr(ui_helpers, "tabulate", lambda data, tablefmt=None: data[0][0])

    sections = helper.render_banner(table_width=20)

    assert sections.heading == "[BANNER]"
    assert "Welcome to CIP Tool" in sections.footer_lines[1]


def test_progress_bar_writes_progress():
    stream = io.StringIO()
    helper = CLIUIHelpers(stream=stream)

    class Clock:
        def __init__(self):
            self._current = 0.0

        def now(self):
            value = self._current
            self._current += 0.2
            return value

        def sleep(self, _seconds):
            pass

    clock = Clock()

    helper.progress_bar(
        "Loading",
        0.3,
        echo=lambda text: None,
        now=clock.now,
        sleep=clock.sleep,
        width=10,
    )

    output = stream.getvalue()
    assert "Loading" in output
    assert output.strip().endswith("0.3s/0.3s")

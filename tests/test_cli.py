"""The command line: argument checks made before a scan starts, and exit statuses. Offline throughout."""
import threading

import pytest

from binwitness import cli

from helpers import make_jar


@pytest.fixture
def jar(tmp_path):
    path = tmp_path / "lib-1.0.jar"
    path.write_bytes(make_jar("org.example", "lib", "1.0"))
    return path


def offline(tmp_path, jar, *extra):
    return ["scan", str(jar), "--offline", "--cache-dir", str(tmp_path / "cache"), "--db-dir", str(tmp_path / "db"),
            *extra]


def test_fail_on_exits_4_when_nothing_was_found_because_nothing_could_be_checked(tmp_path, jar, capsys):
    assert cli.main(offline(tmp_path, jar, "-o", str(tmp_path / "out"), "--fail-on", "high")) == 4
    captured = capsys.readouterr()
    assert "could not check everything" in captured.err and "INCOMPLETE" in captured.out
    assert cli.main(offline(tmp_path, jar, "-o", str(tmp_path / "out"))) == 0


def test_fail_on_exits_4_for_an_input_with_nothing_to_check(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    assert cli.main(offline(tmp_path, tmp_path / "empty", "-o", str(tmp_path / "out"), "--fail-on", "low")) == 4
    assert "found nothing to check" in capsys.readouterr().err


@pytest.mark.parametrize("extra, message", [
    (["--fail-on", "high", "--no-vulns"], "--fail-on needs the vulnerability lookup"),
    (["--maven-repo", "ftp://repo.example/maven"], "--maven-repo takes an http(s) URL"),
])
def test_contradictory_options_are_refused_before_scanning(tmp_path, jar, monkeypatch, capsys, extra, message):
    monkeypatch.setattr(cli, "scan", lambda *a, **k: pytest.fail("scanned"))
    with pytest.raises(SystemExit) as stop:
        cli.main(offline(tmp_path, jar, "-o", str(tmp_path / "out"), *extra))
    assert stop.value.code == 2 and message in capsys.readouterr().err


def test_an_output_path_that_is_a_file_is_refused_before_scanning(tmp_path, jar, monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda *a, **k: pytest.fail("scanned"))
    taken = tmp_path / "report.json"
    taken.write_text("{}")
    with pytest.raises(SystemExit) as stop:
        cli.main(offline(tmp_path, jar, "-o", str(taken)))
    assert stop.value.code == 2 and "is a file" in capsys.readouterr().err


def test_crosscheck_output_must_name_a_file(tmp_path, capsys):
    result, other = tmp_path / "binwitness.json", tmp_path / "other.csv"
    result.write_text("{}")
    other.write_text("component,version,vulnerability\n")
    with pytest.raises(SystemExit) as stop:
        cli.main(["crosscheck", str(result), str(other), "-o", str(tmp_path), "--offline"])
    assert stop.value.code == 2 and "is a directory" in capsys.readouterr().err


def test_ctrl_c_ends_with_130_and_one_line(tmp_path, jar, monkeypatch, capsys):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "scan", interrupted)
    # With lookup threads still running, main() ends the process at once; this test has none to wait for.
    monkeypatch.setattr(threading, "active_count", lambda: 1)
    assert cli.main(offline(tmp_path, jar, "-o", str(tmp_path / "out"))) == 130
    assert capsys.readouterr().err.strip() == "binwitness: interrupted"

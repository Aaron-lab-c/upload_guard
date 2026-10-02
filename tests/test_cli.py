import json

from conftest import SVG_XSS, make_pe, make_png
from upload_guard.cli import main


def test_cli_scan_and_detect(tmp_path, capsys):
    good = tmp_path / "ok.png"
    good.write_bytes(make_png())
    bad = tmp_path / "evil.png"
    bad.write_bytes(make_pe())

    assert main(["scan", str(good)]) == 0
    out = capsys.readouterr().out
    assert "OK" in out and "image/png" in out

    assert main(["scan", str(good), str(bad), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["ok"] is True and payload[1]["ok"] is False
    assert any(f["code"] == "extension.mismatch" for f in payload[1]["findings"])

    assert main(["scan", str(good), "--allow", "application/pdf"]) == 1
    capsys.readouterr()
    assert main(["detect", str(good), str(bad), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["mime"] == "image/png"
    assert main(["scan", str(tmp_path / "missing.png")]) == 2


def test_cli_write_sanitized(tmp_path, capsys):
    svg = tmp_path / "logo.svg"
    svg.write_bytes(SVG_XSS)
    out = tmp_path / "clean.svg"
    assert main(["scan", str(svg), "--write-sanitized", str(out)]) == 0
    assert out.exists() and b"<script" not in out.read_bytes()
    assert main(["scan", str(svg), "--no-sanitize"]) == 1

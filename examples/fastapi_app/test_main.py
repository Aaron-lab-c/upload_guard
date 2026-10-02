# examples/fastapi_app/test_main.py
import main
import pytest
from fastapi.testclient import TestClient
from samples import PE_EXE, PNG, SVG_XSS


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path))
    return TestClient(main.app), tmp_path


def test_accepts_real_png_and_stores_under_safe_name(client):
    c, folder = client
    r = c.post("/upload", files={"file": ("Cat Photo (1).png", PNG, "image/png")})
    assert r.status_code == 200, r.text
    assert r.json()["mime"] == "image/png"
    assert r.json()["filename"] == "Cat Photo (1).png"
    assert (folder / "Cat Photo (1).png").read_bytes() == PNG


def test_path_traversal_filename_is_rejected(client):
    c, folder = client
    r = c.post("/upload", files={"file": ("../../etc/cat.png", PNG, "image/png")})
    assert r.status_code == 422
    assert any(f["code"] == "filename.path_traversal" for f in r.json()["detail"]["findings"])
    assert not list(folder.iterdir())


def test_rejects_exe_disguised_as_png(client):
    c, _ = client
    r = c.post("/upload", files={"file": ("cute.png", PE_EXE, "image/png")})
    assert r.status_code == 415
    codes = {f["code"] for f in r.json()["detail"]["findings"]}
    assert "extension.mismatch" in codes and "type.blocked" in codes


def test_rejects_oversize(client):
    c, _ = client
    r = c.post("/upload", files={"file": ("big.png", PNG + bytes(6 * 1024 * 1024), "image/png")})
    assert r.status_code == 413


def test_svg_is_sanitised_not_rejected(client):
    c, folder = client
    r = c.post("/upload", files={"file": ("logo.svg", SVG_XSS, "image/svg+xml")})
    assert r.status_code == 200, r.text
    assert "svg.script" in r.json()["warnings"]
    stored = (folder / "logo.svg").read_bytes().lower()
    assert b"<script" not in stored and b"onload" not in stored


def test_dependency_form(client):
    c, _ = client
    assert c.post("/avatar", files={"avatar": ("me.png", PNG, "image/png")}).json() == {"mime": "image/png", "size": len(PNG)}
    assert c.post("/avatar", files={"avatar": ("me.png", PE_EXE, "image/png")}).status_code == 415

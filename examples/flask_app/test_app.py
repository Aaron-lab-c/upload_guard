# examples/flask_app/test_app.py
import io

import pytest
from app import create_app
from samples import PE_EXE, PNG, SVG_XSS


@pytest.fixture
def client(tmp_path):
    app = create_app(upload_dir=tmp_path)
    app.testing = True
    return app.test_client(), tmp_path


def post(client, name, data, mimetype="application/octet-stream", url="/upload"):
    return client.post(url, data={"file": (io.BytesIO(data), name, mimetype)}, content_type="multipart/form-data")


def test_png_saved_under_safe_name(client):
    c, folder = client
    r = post(c, "Cat Photo (1).png", PNG, "image/png")
    assert r.status_code == 200, r.data
    assert r.get_json()["filename"] == "Cat Photo (1).png"
    assert (folder / "Cat Photo (1).png").read_bytes() == PNG


def test_path_traversal_filename_is_422(client):
    c, folder = client
    r = post(c, "../../cat.png", PNG, "image/png")
    assert r.status_code == 422
    assert not list(folder.iterdir())


def test_exe_as_png_is_415(client):
    c, _ = client
    r = post(c, "cute.png", PE_EXE, "image/png")
    assert r.status_code == 415
    assert b"does not match detected type" in r.data


def test_svg_sanitised(client):
    c, folder = client
    r = post(c, "logo.svg", SVG_XSS, "image/svg+xml")
    assert r.status_code == 200
    assert "svg.event_handler" in r.get_json()["warnings"]
    assert b"<script" not in (folder / "logo.svg").read_bytes().lower()


def test_check_endpoint_returns_full_report(client):
    c, _ = client
    r = post(c, "cute.png", PE_EXE, "image/png", url="/check")
    body = r.get_json()
    assert r.status_code == 400 and body["ok"] is False
    assert body["detected"]["mime"] == "application/vnd.microsoft.portable-executable"
    assert any(f["code"] == "extension.mismatch" for f in body["findings"])

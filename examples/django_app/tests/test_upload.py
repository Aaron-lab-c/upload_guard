# examples/django_app/tests/test_upload.py
import pytest
from django.test import Client
from samples import PE_EXE, PNG, SVG_XSS


@pytest.fixture
def client(tmp_path, settings_media):
    settings_media(tmp_path)
    return Client(), tmp_path


@pytest.fixture
def settings_media():
    from django.conf import settings

    def _set(path):
        settings.MEDIA_ROOT = path

    return _set


@pytest.mark.parametrize("url", ["/upload/form", "/upload/api"])
def test_png_accepted(client, url):
    c, folder = client
    r = c.post(url, {"file": _upload("../cat.png", PNG, "image/png")})
    assert r.status_code == 200, r.content
    assert r.json()["mime"] == "image/png"
    assert (folder / "cat.png").read_bytes() == PNG


def test_form_rejects_exe_as_png(client):
    c, _ = client
    r = c.post("/upload/form", {"file": _upload("cute.png", PE_EXE, "image/png")})
    assert r.status_code == 400
    codes = {e["code"] for e in r.json()["errors"]["file"]}
    assert "extension_mismatch" in codes and "type_blocked" in codes


def test_api_rejects_and_sanitises(client):
    c, folder = client
    r = c.post("/upload/api", {"file": _upload("cute.png", PE_EXE, "image/png")})
    assert r.status_code == 400 and any(e["code"] == "extension_mismatch" for e in r.json()["errors"])
    r = c.post("/upload/api", {"file": _upload("logo.svg", SVG_XSS, "image/svg+xml")})
    assert r.status_code == 200 and "svg.script" in r.json()["warnings"]
    assert b"<script" not in (folder / "logo.svg").read_bytes().lower()


def _upload(name, data, content_type):
    from django.core.files.uploadedfile import SimpleUploadedFile

    return SimpleUploadedFile(name, data, content_type=content_type)

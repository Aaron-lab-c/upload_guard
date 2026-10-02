"""Framework integrations.

Each framework test skips itself when that framework is not installed, so the
module always collects at least the framework-free tests (pytest exits 5 when
a whole module is skipped, which would fail CI jobs that install one extra).
"""
import io

import pytest

from conftest import make_pdf, make_pe, make_png
from upload_guard import UploadGuard, scan
from upload_guard.integrations import http_status_for, problem_detail


def test_http_status_mapping():
    assert http_status_for(scan(make_png(), filename="a.png", max_size=5)) == 413
    assert http_status_for(scan(make_pe(), filename="a.png")) == 415
    assert http_status_for(scan(make_png(), filename="../a.png")) == 422
    body = problem_detail(scan(make_pe(), filename="a.png"))
    assert body["error"] == "upload_rejected" and body["findings"]


def test_fastapi_integration():
    pytest.importorskip("fastapi", reason="fastapi not installed")
    pytest.importorskip("fastapi.testclient", reason="fastapi testclient (httpx) not installed")
    from fastapi import Depends, FastAPI, File, UploadFile
    from fastapi.testclient import TestClient

    from upload_guard.integrations.fastapi import Guarded, validate_upload

    guard = UploadGuard(allowed=["image/*", "application/pdf"], max_size=1024 * 1024)
    app = FastAPI()

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)):
        result = validate_upload(file, guard)
        data = await file.read()  # position restored → full content still readable
        return {"mime": result.mime, "size": len(data), "safe": result.safe_filename}

    @app.post("/dep")
    def dep(result=Depends(Guarded(guard, field="document"))):
        return {"mime": result.mime, "filename": result.upload.filename}

    client = TestClient(app)
    png = make_png()
    r = client.post("/upload", files={"file": ("cat.png", png, "image/png")})
    assert r.status_code == 200, r.text
    assert r.json() == {"mime": "image/png", "size": len(png), "safe": "cat.png"}

    r = client.post("/upload", files={"file": ("cat.png", make_pe(), "image/png")})
    assert r.status_code == 415
    assert r.json()["detail"]["error"] == "upload_rejected"

    r = client.post("/upload", files={"file": ("x.png", bytes(2 * 1024 * 1024), "image/png")})
    assert r.status_code == 413

    r = client.post("/dep", files={"document": ("a.pdf", make_pdf(), "application/pdf")})
    assert r.status_code == 200 and r.json() == {"mime": "application/pdf", "filename": "a.pdf"}
    r = client.post("/dep", files={"document": ("a.pdf", make_pe(), "application/pdf")})
    assert r.status_code == 415


def test_flask_integration():
    pytest.importorskip("flask", reason="flask not installed")
    from flask import Flask, request

    from upload_guard.integrations.flask import validate_upload

    guard = UploadGuard(allowed=["image/*"])
    app = Flask(__name__)

    @app.post("/upload")
    def upload():
        result = validate_upload(request.files["file"], guard)
        data = request.files["file"].read()
        return {"mime": result.mime, "size": len(data)}

    client = app.test_client()
    png = make_png()
    r = client.post("/upload", data={"file": (io.BytesIO(png), "a.png")}, content_type="multipart/form-data")
    assert r.status_code == 200 and r.get_json() == {"mime": "image/png", "size": len(png)}
    r = client.post("/upload", data={"file": (io.BytesIO(make_pe()), "a.png")}, content_type="multipart/form-data")
    assert r.status_code == 415
    r = client.post("/upload", data={"file": (io.BytesIO(png), "../a.png")}, content_type="multipart/form-data")
    assert r.status_code == 422


def test_django_integration():
    django = pytest.importorskip("django", reason="django not installed")
    from django.conf import settings

    if not settings.configured:
        settings.configure(USE_I18N=False)
        django.setup()
    from django.core.exceptions import ValidationError
    from django.core.files.uploadedfile import SimpleUploadedFile

    from upload_guard.integrations.django import UploadGuardValidator, validate_upload

    guard = UploadGuard(allowed=["image/*"])
    good = SimpleUploadedFile("a.png", make_png(), content_type="image/png")
    result = validate_upload(good, guard)
    assert result.ok and result.filename == "a.png" and result.size == len(make_png())
    assert good.read() == make_png()  # still readable afterwards

    bad = SimpleUploadedFile("a.png", make_pe(), content_type="image/png")
    with pytest.raises(ValidationError) as exc:
        validate_upload(bad, guard)
    assert any(e.code == "extension_mismatch" for e in exc.value.error_list)

    validator = UploadGuardValidator(guard)
    validator(SimpleUploadedFile("b.png", make_png()))
    assert validator.last_result.ok
    with pytest.raises(ValidationError):
        validator(SimpleUploadedFile("b.png", make_pe()))
    assert validator == UploadGuardValidator(guard)
    path, args, kwargs = validator.deconstruct()
    assert path.endswith("UploadGuardValidator")

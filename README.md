# upload_guard

**Pure-Python upload validation: real file-type detection, extension consistency, SVG XSS sanitising, zip-bomb and path-traversal protection — with zero system dependencies.**

[![PyPI](https://img.shields.io/pypi/v/upload_guard.svg)](https://pypi.org/project/upload_guard/)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

`python-magic` needs `libmagic` (`.so` / `.dll`) and breaks on Alpine, distroless images and Windows dev boxes. Most back-ends also forget that an "image" can be a PHP web-shell, that SVGs run JavaScript, and that a 40 KB zip can expand to 4 PB. `upload_guard` fixes all of that in one call, using only the standard library.

> 中文摘要在[最後一節](#繁體中文簡介)。可直接執行的 FastAPI / Flask / Django 範例在 [examples/](examples/)，威脅模型見 [SECURITY.md](SECURITY.md)。

## Contents

1. [Quick start](#quick-start-30-seconds)
2. [What it checks](#what-it-checks)
3. [Install](#install)
4. [Usage](#usage)
5. [Framework integration](#framework-integration) — [FastAPI](#fastapi) · [Django](#django) · [Flask](#flask)
6. [CLI](#cli)
7. [Design notes](#design-notes)
8. [Limitations](#limitations)
9. [繁體中文簡介](#繁體中文簡介)

## Quick start (30 seconds)

```bash
pip install upload_guard
```

<!-- run -->
```python
from upload_guard import UploadGuard, UploadRejected

guard = UploadGuard(allowed=["image/*", "application/pdf", ".docx"], max_size=10 * 1024 * 1024)

png = b"\x89PNG\r\n\x1a\n" + bytes(64)                        # any upload: bytes, path, file object, UploadFile...
result = guard.check(png, filename="cat.png")
print(result.mime, result.safe_filename)                        # image/png cat.png

try:
    guard.check(b"MZ" + bytes(200), filename="cat.png")         # a Windows executable renamed to .png
except UploadRejected as exc:
    print("REJECTED", exc.codes)                                # ['extension.mismatch', 'type.blocked', 'type.not_allowed']
```

In a request handler you would then store `result.sanitized or data` under `result.safe_filename`.

## What it checks

| Module | What it catches |
|---|---|
| **Magic-number sniffer** | Reads the first 2 KiB and identifies ~120 formats (PNG/JPEG/WebP/HEIC/AVIF, PDF, legacy and OOXML Office, ODF, EPUB, ZIP/7z/RAR/tar/gz/xz, PE/ELF/Mach-O, fonts, audio/video, SQLite, Parquet…). Container formats are refined: `RIFF`→WAV/AVI/WebP, `ftyp`→MP4/MOV/HEIC, ZIP→DOCX/XLSX/PPTX/JAR/APK/EPUB, OLE2→DOC/XLS/PPT/MSG/MSI. Text is classified as SVG/HTML/XML/JSON/PHP/shell/PEM/vCard… the way a browser would sniff it. |
| **Extension consistency** | Declared extension vs. detected type (with aliases `jpg`/`jpeg`, `tif`/`tiff`…); allow/deny rules like `"image/*"`, `"application/pdf"`, `".docx"`, `"category:archive"`; declared `Content-Type` vs. reality. |
| **Filename safety** | `../` traversal, absolute paths, null bytes, control characters, **RTLO / bidi-override spoofing** (`invoice_‮gnp.exe`), zero-width characters, Windows reserved names (`CON`, `LPT1`), `.htaccess`/`web.config`, dangerous and double extensions (`shell.php.jpg`). Plus `sanitize_filename()` that returns something safe to store. |
| **SVG XSS** | `<script>`, `on*` handlers, `javascript:`/`data:text/html` URIs (including obfuscated `java\tscript:`), `<foreignObject>`, HTML elements, external `<use>`/`<image>` references, CSS `expression()`/`@import`/`url()`, `<!ENTITY>` (XXE / billion laughs), `<?xml-stylesheet?>`. Either **report** or **sanitise** (returns clean bytes). |
| **Archive bombs** | ZIP: total uncompressed size, compression ratio, entry count, nested archives (recursively, bounded), overlapping-entry bombs, lying headers (optional real decompression with a cap), encrypted entries, symlinks, **Zip Slip** paths. gzip/bzip2/xz/tar: bounded streaming decompression that never buffers more than 64 KiB, tar header walk (GNU long names, PAX), **Tar Slip**, symlink escapes, device nodes. Also applies to DOCX/XLSX/PPTX/ODF (they are zips). |
| **Polyglots** | Secondary signatures inside images/documents (`<?php` in a GIF comment, ZIP after a GIF = GIFAR, PDF inside PNG, `<script>` in JPEG) and data appended after the format's EOF marker (PNG `IEND`, JPEG `FFD9`, GIF `;`, PDF `%%EOF`) — the classic "image with a web-shell appended" trick. |

Everything runs with hard limits on bytes read, elements parsed and decompressed output, so the validator itself cannot be used as a DoS vector.

## Install

```bash
pip install upload_guard
```

No compiled extensions, no `libmagic`, no third-party runtime dependencies. Python 3.8+.

## Usage

### One-shot functions

```python
from upload_guard import check, scan, detect_type, sanitize_svg, sanitize_filename, inspect_archive

detect_type(b"\x89PNG\r\n\x1a\n...").mime          # 'image/png'
detect_type("/tmp/upload.bin")                      # DetectedType(mime=..., extensions=(...), category=...)

result = scan(data, filename="cat.png")              # never raises
result.ok, result.mime, result.findings

check(data, filename="cat.png", allowed=["image/*"]) # raises UploadRejected

clean = sanitize_svg(svg_bytes).sanitized            # bytes without scripts/handlers/external refs
sanitize_filename("../../etc/passwd\x00.png")        # 'passwd.png'
```

### Policy

```python
from upload_guard import UploadGuard, Policy, Severity, ArchiveLimits, SvgPolicy

guard = UploadGuard(
    allowed=["image/*", "application/pdf", ".docx", ".xlsx"],  # evaluated against the *detected* type
    blocked=["category:executable", "category:script"],        # default
    max_size=20 * 1024 * 1024,
    require_extension=True,         # filename must have an extension
    strict_extension=True,          # ...and it must match the detected type
    check_content_type=True,        # declared Content-Type mismatch → LOW finding
    allow_unknown=False,            # unidentifiable binary → rejected
    sanitize_svg=True,              # clean SVGs instead of rejecting them
    svg_policy=SvgPolicy(allow_external_references=False, allow_data_images=True),
    inspect_archives=True,
    archive_limits=ArchiveLimits(
        max_total_uncompressed=512 * 1024 * 1024,
        max_ratio=100.0,
        max_entries=10_000,
        max_nesting=1,
        verify_sizes=False,         # True: actually decompress ZIP entries (bounded) to catch lying headers
        allow_symlinks=False,
    ),
    polyglot_scan_limit=1024 * 1024,
    check_trailing_data=True,
    reject_threshold=Severity.MEDIUM,   # findings at or above this severity reject the upload
)
```

Every `UploadGuard` keyword is a field of `Policy`; you can also pass a `Policy` object and override individual fields: `UploadGuard(policy, max_size=5_000_000)`.

### Reading the result

```python
result = guard.scan(upload)

result.ok                    # bool
result.detected              # DetectedType(mime, extensions, description, category)
result.mime                  # 'image/png'
result.extension             # extension to store the file with (detected, else declared)
result.safe_filename         # sanitised filename, extension added if missing
result.size
result.findings              # list[Finding(code, severity, message, detail, remediated)]
result.errors                # findings that caused rejection
result.warnings              # everything else (including remediated SVG problems)
result.archive               # ArchiveReport(entry_count, total_uncompressed, ratio, nested_archives, unsafe_paths…)
result.sanitized             # cleaned SVG bytes when sanitising was enabled, else None
result.to_dict()             # JSON-serialisable
```

Finding codes are stable strings, grouped by prefix: `size.*`, `type.*`, `extension.*`, `content_type.*`, `filename.*`, `svg.*`, `archive.*`, `polyglot.*`.

Severity semantics:

| Severity | Meaning | Examples |
|---|---|---|
| `CRITICAL` | Definitely hostile | `svg.script`, `archive.bomb_size`, `filename.path_traversal`, `polyglot.embedded_php` |
| `HIGH` | Violates policy or strongly suspicious | `extension.mismatch`, `type.blocked`, `size.too_large`, `svg.foreign_object` |
| `MEDIUM` | Suspicious, usually worth rejecting (default threshold) | `polyglot.trailing_data`, `svg.external_reference`, `filename.double_extension` (executable inner ext) |
| `LOW` | Informational / lying browsers | `content_type.mismatch`, `filename.hidden`, `archive.encrypted` |
| `INFO` | Notes | `filename.double_extension` (`.tar.gz`) |

## Framework integration

Inputs are duck-typed, so plain `bytes`, `io.BytesIO`, paths, open files, Starlette/FastAPI `UploadFile`, Django `UploadedFile` and Werkzeug/Flask `FileStorage` all work directly. The stream position is always restored, so you can still `save()` / `read()` afterwards.

### FastAPI

Full runnable app with tests: [examples/fastapi_app](examples/fastapi_app). `validate_upload` raises
`HTTPException` 413 / 415 / 422 with a JSON body listing the findings; `Guarded(...)` is the same check as a
dependency.

<!-- include: examples/fastapi_app/main.py -->
```python
# examples/fastapi_app/main.py
import os
from pathlib import Path

from fastapi import Depends, FastAPI, File, UploadFile

from upload_guard import UploadGuard
from upload_guard.integrations.fastapi import Guarded, validate_upload

# ---- 1. 設定一次：允許的類型以「偵測到的真實類型」為準 -------------------------------
guard = UploadGuard(
    allowed=["image/*", "application/pdf", ".docx"],
    max_size=5 * 1024 * 1024,
    sanitize_svg=True,                        # SVG 會被消毒後接受，而不是整個拒絕
)

app = FastAPI()


def upload_dir() -> Path:
    path = Path(os.environ.get("UPLOAD_DIR", "uploads"))
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---- 2. 在 handler 內驗證：失敗時自動回 413 / 415 / 422 --------------------------------
@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    result = validate_upload(file, guard)     # raises HTTPException on rejection
    data = result.sanitized or await file.read()   # 消毒後的 SVG，否則原始內容（位置已還原）
    (upload_dir() / result.safe_filename).write_bytes(data)
    return {
        "mime": result.mime,
        "filename": result.safe_filename,
        "warnings": [f.code for f in result.warnings],
    }


# ---- 3. 或者當成 dependency：欄位名由 field= 決定 -----------------------------------------
@app.post("/avatar")
async def avatar(result=Depends(Guarded(guard, field="avatar"))):
    return {"mime": result.mime, "size": result.size}
```

### Django

Full runnable project with tests: [examples/django_app](examples/django_app). `UploadGuardValidator` works on
`forms.FileField` and on model `FileField` / `ImageField` (it is `@deconstructible`, so migrations are fine);
`validate_upload` raises `ValidationError` with one error per finding.

<!-- include: examples/django_app/views.py -->
```python
# examples/django_app/views.py
from pathlib import Path

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from upload_guard import UploadGuard
from upload_guard.integrations.django import UploadGuardValidator, validate_upload

# ---- 1. 設定一次 --------------------------------------------------------------------
guard = UploadGuard(allowed=["image/*", "application/pdf"], max_size=5 * 1024 * 1024)


# ---- 2a. 表單 / Model 欄位：掛 validator，錯誤進 form.errors ------------------------------
class UploadForm(forms.Form):
    file = forms.FileField(validators=[UploadGuardValidator(guard)])


@csrf_exempt            # 範例用；真實專案請走 CSRF token 或 API key 驗證
@require_POST
def upload_form(request):
    form = UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        return JsonResponse({"errors": form.errors.get_json_data()}, status=400)
    f = form.cleaned_data["file"]
    result = guard.scan(f)                                  # 取得 ScanResult（消毒結果、安全檔名）
    _store(result, f)
    return JsonResponse({"mime": result.mime, "filename": result.safe_filename})


# ---- 2b. 直接在 view 內驗證：失敗時拋 ValidationError -------------------------------------
@csrf_exempt
@require_POST
def upload_api(request):
    f = request.FILES["file"]
    try:
        result = validate_upload(f, guard)
    except ValidationError as exc:
        return JsonResponse({"errors": [{"code": e.code, "message": e.message} for e in exc.error_list]}, status=400)
    _store(result, f)
    return JsonResponse({"mime": result.mime, "filename": result.safe_filename, "warnings": [w.code for w in result.warnings]})


def _store(result, uploaded):
    root = Path(settings.MEDIA_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    data = result.sanitized if result.sanitized is not None else uploaded.read()   # 位置已還原
    (root / result.safe_filename).write_bytes(data)
```

### Flask

Full runnable app with tests: [examples/flask_app](examples/flask_app). `validate_upload` aborts with the
matching Werkzeug `HTTPException` (413 / 415 / 422); use `guard.scan()` when you want to shape the response
yourself.

<!-- include: examples/flask_app/app.py -->
```python
# examples/flask_app/app.py
import os
from pathlib import Path

from flask import Flask, jsonify, request

from upload_guard import UploadGuard
from upload_guard.integrations.flask import validate_upload

# ---- 1. 設定一次 --------------------------------------------------------------------
guard = UploadGuard(allowed=["image/*", "application/pdf"], max_size=5 * 1024 * 1024)


def create_app(upload_dir=None):
    app = Flask(__name__)
    app.config["UPLOAD_DIR"] = Path(upload_dir or os.environ.get("UPLOAD_DIR", "uploads"))
    app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024   # 第一道防線：Werkzeug 直接擋掉超大請求

    # ---- 2. 驗證失敗時 validate_upload 會 abort(413/415/422)，Flask 回對應錯誤頁 -------------
    @app.post("/upload")
    def upload():
        f = request.files["file"]
        result = validate_upload(f, guard)
        app.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)
        target = app.config["UPLOAD_DIR"] / result.safe_filename   # 永遠用消毒後的檔名
        if result.sanitized is not None:
            target.write_bytes(result.sanitized)                     # 消毒後的 SVG
        else:
            f.save(target)                                           # 串流位置已還原，可直接存
        return jsonify(mime=result.mime, filename=result.safe_filename, warnings=[w.code for w in result.warnings])

    # ---- 3. 想自己決定回應格式：用 scan() 取得完整結果 -------------------------------------------
    @app.post("/check")
    def check():
        result = guard.scan(request.files["file"])
        return jsonify(result.to_dict()), (200 if result.ok else 400)

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
```

## CLI

```bash
upload_guard scan photo.png report.pdf --allow "image/*" --allow application/pdf
upload_guard scan logo.svg --write-sanitized clean.svg
upload_guard scan suspicious.zip --json
upload_guard detect *.bin
```

Exit code `0` = all accepted, `1` = at least one rejected, `2` = I/O error.

## Design notes

* **Detected, not declared.** Allow-lists and extension checks are evaluated against the sniffed type. A `.png` that is really a PE file fails `extension.mismatch` *and* `type.blocked` even if `image/*` is allowed.
* **Browsers sniff too.** Text starting with `<html`, `<script`, `<svg` is classified as HTML/SVG regardless of extension, because that is what a browser will render — which is exactly how stored-XSS via "text" uploads happens.
* **Bounded everything.** 2 KiB for sniffing, 1 MiB (configurable) for polyglot scanning, 64 KiB tail for trailing-data checks, streaming decompression with a hard output cap, element/depth caps for SVG parsing. The validator cannot be turned into the bomb.
* **Remediation is tracked.** When an SVG is sanitised, the findings stay in `result.findings` with `remediated=True` for logging, but they don't reject the upload.
* **Lossless for callers.** Stream positions are restored; owned streams (paths, bytes) are closed; framework upload objects are left open.

## Limitations

* Encrypted ZIP entries, 7z, RAR and Zstandard archives are identified but their contents are not inspected (they produce `archive.encrypted` / no report).
* Detection is signature-based, not a parser: a valid-looking header followed by garbage is still "a PNG". Pair with an image decoder (Pillow `Image.verify()`) when you need structural validation.
* SVG sanitising uses an allow-leaning deny-list; if you need a strict allow-list of elements use `SvgPolicy.blocked_elements` to tighten further, or reject SVGs outright by excluding `image/svg+xml` from `allowed`.

## 繁體中文簡介

`upload_guard` 是不依賴 `libmagic` 的純 Python 上傳檔案檢驗套件：

* **Magic Number 鑑定**：讀前 2048 bytes 判斷真實 MIME（含 docx/xlsx/pptx、doc/xls/ppt、HEIC、WebM 等容器格式細分）。
* **副檔名一致性**：宣告副檔名／Content-Type 與偵測結果比對；`allowed=["image/*", ".pdf"]` 以「真實類型」為準。
* **檔名防護**：`../`、null byte、RTLO 字元偽裝、Windows 保留名、雙重副檔名；`sanitize_filename()` 產生安全檔名。
* **SVG 消毒**：移除 `<script>`、`on*`、`javascript:`、`<foreignObject>`、外部參照、危險 CSS、XML 實體宣告。
* **壓縮炸彈 / Zip Slip**：ZIP/TAR/gzip/bz2/xz 解壓大小與比率預估、巢狀壓縮、重疊項目、路徑穿越、symlink，全程有界串流，不落地。
* **Polyglot**：圖片中夾帶 PHP/ZIP/PDF/HTML 簽章、EOF 後尾隨資料。
* **框架友好**：直接接受 FastAPI `UploadFile`、Django `UploadedFile`、Flask `FileStorage`、`bytes`、`BytesIO`、路徑。

## License

MIT

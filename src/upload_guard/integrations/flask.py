"""Flask / Werkzeug integration.

::

    from flask import Flask, request
    from upload_guard import UploadGuard
    from upload_guard.integrations.flask import validate_upload

    guard = UploadGuard(allowed=["image/*"], max_size=5 * 1024 * 1024)
    app = Flask(__name__)

    @app.post("/upload")
    def upload():
        result = validate_upload(request.files["file"], guard)   # aborts with 413/415/422
        request.files["file"].save(f"uploads/{result.safe_filename}")
        return {"mime": result.mime}
"""
from __future__ import annotations

from typing import Any, Optional

from ..guard import UploadGuard
from ..types import ScanResult
from ._http import http_status_for, problem_detail

try:  # pragma: no cover - import guard
    from werkzeug.exceptions import HTTPException, default_exceptions
except ImportError as exc:  # pragma: no cover
    raise ImportError("upload_guard.integrations.flask requires Flask/Werkzeug: pip install flask") from exc


def exception_for(result: ScanResult) -> HTTPException:
    status = http_status_for(result)
    exc_class = default_exceptions.get(status, HTTPException)
    exc = exc_class(description=problem_detail(result)["message"])
    exc.upload_guard_result = result  # type: ignore[attr-defined]
    return exc


def validate_upload(file_storage: Any, guard: Optional[UploadGuard] = None, **policy: Any) -> ScanResult:
    """Validate a Werkzeug ``FileStorage``; raises a Werkzeug ``HTTPException``
    (which Flask turns into the matching error response)."""
    g = guard or UploadGuard(**policy)
    result = g.scan(file_storage)
    if not result.ok:
        raise exception_for(result)
    return result


__all__ = ["validate_upload", "exception_for"]

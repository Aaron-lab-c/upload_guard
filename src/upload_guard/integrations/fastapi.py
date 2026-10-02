"""FastAPI / Starlette integration.

::

    from fastapi import FastAPI, UploadFile, File, Depends
    from upload_guard import UploadGuard
    from upload_guard.integrations.fastapi import Guarded, validate_upload

    guard = UploadGuard(allowed=["image/*", "application/pdf"], max_size=5 * 1024 * 1024)
    app = FastAPI()

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)):
        result = validate_upload(file, guard)     # raises HTTPException 413/415/422
        data = result.sanitized or await file.read()
        ...

    # or as a dependency that yields the ScanResult (form field name "file" by default)
    @app.post("/upload2")
    async def upload2(result = Depends(Guarded(guard))):
        return {"mime": result.mime, "safe_filename": result.safe_filename}
"""
from __future__ import annotations

import inspect
from typing import Any, Callable, Optional

from ..guard import UploadGuard
from ..types import ScanResult
from ._http import http_status_for, problem_detail

try:  # pragma: no cover - import guard
    from fastapi import File, HTTPException, UploadFile
except ImportError as exc:  # pragma: no cover
    raise ImportError("upload_guard.integrations.fastapi requires fastapi: pip install fastapi") from exc


def exception_for(result: ScanResult) -> HTTPException:
    return HTTPException(status_code=http_status_for(result), detail=problem_detail(result))


def validate_upload(upload: Any, guard: Optional[UploadGuard] = None, **policy: Any) -> ScanResult:
    """Validate a Starlette ``UploadFile`` (or anything upload-shaped).

    Raises :class:`fastapi.HTTPException` on rejection. The file position is
    restored, so ``await upload.read()`` still works afterwards.
    """
    g = guard or UploadGuard(**policy)
    result = g.scan(upload)
    if not result.ok:
        raise exception_for(result)
    return result


def Guarded(guard: Optional[UploadGuard] = None, field: str = "file", **policy: Any) -> Callable[..., ScanResult]:
    """Build a dependency ``Depends(Guarded(guard))`` that validates form field ``field``
    and returns the :class:`ScanResult`. The original ``UploadFile`` is available as
    ``result.upload``."""
    g = guard or UploadGuard(**policy)

    def dependency(**kwargs: Any) -> ScanResult:
        upload = kwargs[field]  # FastAPI passes the form field by the name in __signature__
        result = validate_upload(upload, g)
        result.upload = upload  # type: ignore[attr-defined]
        return result

    param = inspect.Parameter(field, inspect.Parameter.POSITIONAL_OR_KEYWORD, default=File(...), annotation=UploadFile)
    dependency.__signature__ = inspect.Signature([param], return_annotation=ScanResult)  # type: ignore[attr-defined]
    dependency.__name__ = "guarded_%s" % field
    return dependency


__all__ = ["validate_upload", "Guarded", "exception_for"]

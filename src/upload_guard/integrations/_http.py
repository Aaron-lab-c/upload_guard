"""Framework-neutral HTTP mapping shared by the integrations."""
from __future__ import annotations

from typing import Any, Dict

from ..types import ScanResult


def http_status_for(result: ScanResult) -> int:
    """Pick an HTTP status for a rejected upload.

    * 413 Payload Too Large – size limits
    * 415 Unsupported Media Type – type/extension problems
    * 422 Unprocessable Entity – everything else (malicious content, bad filename)
    """
    codes = {f.code for f in result.errors}
    if any(c.startswith("size.") for c in codes):
        return 413
    if any(c.startswith(("type.", "extension.", "content_type.")) for c in codes):
        return 415
    return 422


def problem_detail(result: ScanResult) -> Dict[str, Any]:
    """A JSON-friendly error body."""
    return {
        "error": "upload_rejected",
        "message": "; ".join(f.message for f in result.errors) or "upload rejected",
        "detected_type": result.detected.mime,
        "findings": [f.to_dict() for f in result.errors],
    }

"""Exception hierarchy."""
from __future__ import annotations

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:  # pragma: no cover
    from .types import Finding, ScanResult


class UploadGuardError(Exception):
    """Base class for all upload_guard errors."""


class UnsupportedSource(UploadGuardError, TypeError):
    """The object passed in is not something upload_guard knows how to read."""


class UploadRejected(UploadGuardError, ValueError):
    """Raised by :meth:`UploadGuard.check` when the upload fails the policy.

    ``result`` holds the full :class:`ScanResult`; ``findings`` is a shortcut
    to the findings that caused the rejection.
    """

    def __init__(self, result: "ScanResult") -> None:
        self.result = result
        self.findings: List["Finding"] = result.errors
        message = "; ".join(f"[{f.code}] {f.message}" for f in self.findings) or "upload rejected"
        super().__init__(message)

    @property
    def codes(self) -> List[str]:
        return [f.code for f in self.findings]

"""Django integration.

::

    from upload_guard import UploadGuard
    from upload_guard.integrations.django import UploadGuardValidator, validate_upload

    guard = UploadGuard(allowed=["image/*"], max_size=2 * 1024 * 1024)

    class Avatar(models.Model):
        image = models.ImageField(upload_to="avatars/", validators=[UploadGuardValidator(guard)])

    class UploadForm(forms.Form):
        file = forms.FileField(validators=[UploadGuardValidator(allowed=["application/pdf"])])

    # or imperatively in a view
    result = validate_upload(request.FILES["file"], guard)   # raises ValidationError
"""
from __future__ import annotations

from typing import Any, Optional

from ..guard import UploadGuard
from ..types import ScanResult

try:  # pragma: no cover - import guard
    from django.core.exceptions import ValidationError
    from django.utils.deconstruct import deconstructible
except ImportError as exc:  # pragma: no cover
    raise ImportError("upload_guard.integrations.django requires Django: pip install django") from exc


def validation_error_for(result: ScanResult) -> ValidationError:
    errors = [ValidationError(f.message, code=f.code.replace(".", "_"), params=f.detail) for f in result.errors]
    return ValidationError(errors or [ValidationError("Upload rejected", code="upload_rejected")])


def validate_upload(uploaded_file: Any, guard: Optional[UploadGuard] = None, **policy: Any) -> ScanResult:
    """Validate a Django ``UploadedFile``; raises ``ValidationError`` on rejection."""
    g = guard or UploadGuard(**policy)
    result = g.scan(uploaded_file)
    if not result.ok:
        raise validation_error_for(result)
    return result


@deconstructible
class UploadGuardValidator:
    """Field validator usable on ``FileField`` / ``ImageField`` (forms and models).

    Pass either a configured :class:`UploadGuard` or policy keyword arguments.
    The last :class:`ScanResult` is kept on ``validator.last_result``.
    """

    def __init__(self, guard: Optional[UploadGuard] = None, **policy: Any) -> None:
        self._policy = policy
        self.guard = guard or UploadGuard(**policy)
        self.last_result: Optional[ScanResult] = None

    def __call__(self, value: Any) -> None:
        if value in (None, ""):
            return
        target = getattr(value, "file", value)
        # FieldFile wrapping an already-stored file: open it if needed
        if hasattr(value, "open") and not hasattr(value, "chunks") and not hasattr(target, "read"):
            value.open("rb")
            target = value.file
        self.last_result = self.guard.scan(target if hasattr(target, "read") else value, filename=getattr(value, "name", None))
        if not self.last_result.ok:
            raise validation_error_for(self.last_result)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, UploadGuardValidator) and other.guard.policy == self.guard.policy

    def __hash__(self) -> int:  # pragma: no cover
        return hash(repr(self.guard.policy))


__all__ = ["UploadGuardValidator", "validate_upload", "validation_error_for"]

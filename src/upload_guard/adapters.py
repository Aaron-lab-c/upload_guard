"""Turn *anything upload-shaped* into a seekable binary stream plus metadata.

Supported inputs (duck-typed, no framework imports):

* ``bytes`` / ``bytearray`` / ``memoryview``
* ``str`` / ``os.PathLike`` paths
* any binary file object (``io.BytesIO``, open files, ``tempfile`` objects)
* Starlette / FastAPI ``UploadFile`` (``.file``, ``.filename``, ``.content_type``, ``.size``)
* Django ``UploadedFile`` (``.name``, ``.size``, ``.content_type``, ``.read``/``.seek``)
* Werkzeug / Flask ``FileStorage`` (``.stream``, ``.filename``, ``.mimetype``)

The stream position is captured on entry and restored on :meth:`FileSource.close`,
so frameworks can still save the file afterwards.
"""
from __future__ import annotations

import io
import os
import tempfile
from typing import Any, BinaryIO, Optional

from .exceptions import UnsupportedSource

_SPOOL_MAX = 8 * 1024 * 1024


class FileSource:
    """A seekable binary stream with optional ``filename`` / ``content_type`` / ``size``."""

    def __init__(
        self,
        stream: BinaryIO,
        *,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        size: Optional[int] = None,
        owns_stream: bool = False,
        oversized: bool = False,
    ) -> None:
        self.stream = stream
        self.filename = filename
        self.content_type = content_type
        self._size = size
        self.owns_stream = owns_stream
        self.oversized = oversized  # non-seekable input exceeded the read cap
        try:
            self._start_pos = stream.tell()
        except (OSError, ValueError, AttributeError):
            self._start_pos = 0

    # -- construction -------------------------------------------------------------
    @classmethod
    def from_any(
        cls,
        obj: Any,
        *,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        max_read: Optional[int] = None,
    ) -> "FileSource":
        if isinstance(obj, FileSource):
            if filename is not None:
                obj.filename = filename
            if content_type is not None:
                obj.content_type = content_type
            return obj

        if isinstance(obj, (bytes, bytearray, memoryview)):
            data = bytes(obj)
            return cls(io.BytesIO(data), filename=filename, content_type=content_type, size=len(data), owns_stream=True)

        if isinstance(obj, (str, os.PathLike)):
            path = os.fspath(obj)
            fh = open(path, "rb")  # noqa: SIM115 - closed by FileSource.close()
            size = os.fstat(fh.fileno()).st_size
            return cls(fh, filename=filename or os.path.basename(path), content_type=content_type, size=size, owns_stream=True)

        # Starlette / FastAPI UploadFile
        inner = getattr(obj, "file", None)
        if inner is not None and hasattr(inner, "read") and hasattr(obj, "filename"):
            return cls(
                _ensure_seekable(inner, max_read)[0],
                filename=filename or _str_or_none(getattr(obj, "filename", None)),
                content_type=content_type or _str_or_none(getattr(obj, "content_type", None)),
                size=_int_or_none(getattr(obj, "size", None)),
            )

        # Werkzeug FileStorage
        inner = getattr(obj, "stream", None)
        if inner is not None and hasattr(inner, "read") and hasattr(obj, "filename"):
            stream, owns, oversized = _ensure_seekable(inner, max_read)
            return cls(
                stream,
                filename=filename or _str_or_none(getattr(obj, "filename", None)),
                content_type=content_type or _str_or_none(getattr(obj, "mimetype", None) or getattr(obj, "content_type", None)),
                size=_int_or_none(getattr(obj, "content_length", None)) or None,
                owns_stream=owns,
                oversized=oversized,
            )

        # Django UploadedFile (proxies read/seek to .file) or any file-like object
        if hasattr(obj, "read"):
            django_name = getattr(obj, "name", None) if hasattr(obj, "chunks") else None
            stream, owns, oversized = _ensure_seekable(obj, max_read)
            name = filename
            if name is None:
                raw_name = django_name if django_name is not None else getattr(obj, "name", None)
                if isinstance(raw_name, str):
                    name = os.path.basename(raw_name) if not hasattr(obj, "chunks") else raw_name
            ctype = content_type or _str_or_none(getattr(obj, "content_type", None))
            size = _int_or_none(getattr(obj, "size", None)) if hasattr(obj, "chunks") else None
            return cls(stream, filename=name, content_type=ctype, size=size, owns_stream=owns, oversized=oversized)

        raise UnsupportedSource("cannot read uploads from %r" % type(obj).__name__)

    # -- reading helpers -------------------------------------------------------------
    @property
    def size(self) -> Optional[int]:
        if self._size is None:
            try:
                pos = self.stream.tell()
                self.stream.seek(0, os.SEEK_END)
                self._size = self.stream.tell()
                self.stream.seek(pos)
            except (OSError, ValueError, AttributeError):
                return None
        return self._size

    def read_at(self, offset: int, n: int) -> bytes:
        pos = self.stream.tell()
        try:
            self.stream.seek(offset)
            return self.stream.read(n) or b""
        finally:
            self.stream.seek(pos)

    def read_head(self, n: int) -> bytes:
        return self.read_at(0, n)

    def read_all(self, cap: Optional[int] = None) -> Optional[bytes]:
        """Whole content, or None when it exceeds ``cap`` bytes."""
        if cap is not None and self.size is not None and self.size > cap:
            return None
        pos = self.stream.tell()
        try:
            self.stream.seek(0)
            if cap is None:
                return self.stream.read() or b""
            data = self.stream.read(cap + 1) or b""
            return None if len(data) > cap else data
        finally:
            self.stream.seek(pos)

    # -- lifecycle -------------------------------------------------------------------
    def restore(self) -> None:
        try:
            self.stream.seek(self._start_pos)
        except (OSError, ValueError, AttributeError):
            pass

    def close(self) -> None:
        if self.owns_stream:
            try:
                self.stream.close()
            except Exception:  # noqa: BLE001
                pass
        else:
            self.restore()

    def __enter__(self) -> "FileSource":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _str_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _int_or_none(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _is_seekable(stream: Any) -> bool:
    try:
        if hasattr(stream, "seekable") and not stream.seekable():
            return False
        pos = stream.tell()
        stream.seek(pos)
        return True
    except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
        return False


def _ensure_seekable(stream: Any, max_read: Optional[int]):
    """Return ``(seekable_stream, owns, oversized)``; spools non-seekable input to a temp file."""
    if _is_seekable(stream):
        return stream, False, False
    spool = tempfile.SpooledTemporaryFile(max_size=_SPOOL_MAX)
    remaining = None if max_read is None else max_read + 1
    oversized = False
    while True:
        chunk = stream.read(64 * 1024 if remaining is None else min(64 * 1024, remaining))
        if not chunk:
            break
        spool.write(chunk)
        if remaining is not None:
            remaining -= len(chunk)
            if remaining <= 0:
                oversized = True
                break
    spool.seek(0)
    return spool, True, oversized

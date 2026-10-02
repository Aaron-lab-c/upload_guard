"""Entry points for magic-number detection."""
from __future__ import annotations

from typing import BinaryIO, Optional, Union

from ..types import UNKNOWN_TYPE, DetectedType
from . import signatures as S
from .containers import read_at, refine
from .signatures import ORDERED_SIGNATURES
from .text import detect_text

#: How many leading bytes are needed for a confident detection.
HEADER_SIZE = 2048

# Signatures that live beyond HEADER_SIZE; checked via the stream when available.
_FAR_SIGNATURES = ((0x8001, b"CD001", S.ISO),)


def detect(head: Union[bytes, bytearray, memoryview], stream: Optional[BinaryIO] = None) -> DetectedType:
    """Detect the real type of ``head`` (the first bytes of a file).

    ``stream`` is optional; when given it must be seekable and is used only for
    cheap deeper peeks (ZIP central directory, OLE2 directory, far signatures).
    The stream position is always restored.
    """
    head = bytes(head)
    if not head:
        return UNKNOWN_TYPE
    for sig in ORDERED_SIGNATURES:
        if sig.matches(head):
            refined = refine(sig.type, head, stream)
            if refined is not None:
                return refined
    if stream is not None and len(head) >= HEADER_SIZE:
        for offset, magic, t in _FAR_SIGNATURES:
            if read_at(stream, offset, len(magic)) == magic:
                return t
    text_type = detect_text(head)
    return text_type if text_type is not None else UNKNOWN_TYPE


def detect_stream(stream: BinaryIO, header_size: int = HEADER_SIZE) -> DetectedType:
    """Detect the type of a seekable binary stream, restoring its position."""
    pos = stream.tell()
    try:
        stream.seek(0)
        head = stream.read(header_size) or b""
    finally:
        stream.seek(pos)
    return detect(head, stream)


def detect_bytes(data: bytes, header_size: int = HEADER_SIZE) -> DetectedType:
    import io

    return detect(data[:header_size], io.BytesIO(data))

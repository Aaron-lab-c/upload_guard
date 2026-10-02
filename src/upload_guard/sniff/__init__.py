"""Pure-Python magic-number sniffing."""
from .detector import HEADER_SIZE, detect, detect_bytes, detect_stream

__all__ = ["detect", "detect_stream", "detect_bytes", "HEADER_SIZE"]

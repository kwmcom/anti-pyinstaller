"""
Common constants and utility functions for anti-pyinstaller modules.
"""

import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PyInstallerInfo:
    """Information extracted from a PyInstaller executable."""

    is_pyinstaller: bool
    version: str
    python_version: tuple[int, int]
    platform: str
    is_encrypted: bool
    entry_point: str | None
    file_count: int


@dataclass
class TOCEntry:
    """Table of Contents entry from PyInstaller archive."""

    name: str
    offset: int
    size: int
    compressed_size: int
    is_compressed: bool
    entry_type: bytes


# Magic bytes patterns for finding PyInstaller cookie
MAGIC_PATTERNS = [
    b"MEI\x0c\x0b\x0a\x0b\x0e",
    b"MEI\x0c\x0b\x0a\x0e",
    b"MEI\x0c\x0b\x0d\x0e",
    b"MEI\x0c\x0b\x0c\x0e",
    b"MEI\x0c\x0b\x0b\x0e",
]

# Cookie sizes for different PyInstaller versions
PYINST20_COOKIE_SIZE = 24
PYINST21_COOKIE_SIZE = 88

# Safety limits
MAX_TOC_ENTRIES = 10000
MAX_ENTRY_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_OVERLAY_SIZE = 500 * 1024 * 1024  # 500 MB

# Python version mapping from .pyc magic numbers
PYC_MAGIC_TO_VERSION = {
    b"\x33\x0d\x0d\x0a": (3, 1),
    b"\x34\x0d\x0d\x0a": (3, 2),
    b"\xbb\x0d\x0d\x0a": (3, 3),
    b"\xbc\x0d\x0d\x0a": (3, 4),
    b"\xbd\x0d\x0d\x0a": (3, 5),
    b"\xbe\x0d\x0d\x0a": (3, 6),
    b"\xbf\x0d\x0d\x0a": (3, 7),
    b"\xc0\x0d\x0d\x0a": (3, 8),
    b"\xc1\x0d\x0d\x0a": (3, 9),
    b"\xc2\x0d\x0d\x0a": (3, 10),
    b"\xc3\x0d\x0d\x0a": (3, 11),
    b"\xc4\x0d\x0d\x0a": (3, 12),
    b"\xc5\x0d\x0d\x0a": (3, 13),
    b"\xc6\x0d\x0d\x0a": (3, 14),
    b"\x42\x0d\x0d\x0a": (2, 7),
    b"\xeb\x0d\x0d\x0a": (3, 0),
    b"\xec\x0d\x0d\x0a": (3, 1),
    b"\xed\x0d\x0d\x0a": (3, 2),
    b"\xee\x0d\x0d\x0a": (3, 3),
    b"\xef\x0d\x0d\x0a": (3, 4),
    b"\xf0\x0d\x0d\x0a": (3, 5),
    b"\xf1\x0d\x0d\x0a": (3, 6),
}


def _detect_platform(path: Path) -> str:
    """Detect platform from file magic bytes."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\x7fELF":
            return "linux"
        elif magic.startswith(b"MZ"):
            return "windows"
    return "unknown"


def _find_cookie(path: Path) -> int:
    """Find PyInstaller cookie in file."""
    with open(path, "rb") as f:
        f.seek(0, 2)
        file_size = f.tell()
        return _find_cookie_from_file(f, file_size)


def _find_cookie_from_file(f, file_size: int) -> int:
    """Find PyInstaller cookie from file object."""
    # Use file_size passed as argument instead of calculating it inside the function

    chunk_size = 8192
    cookie_pos = -1

    for magic_pattern in MAGIC_PATTERNS:
        end_pos = file_size
        while True:
            start_pos = end_pos - chunk_size if end_pos >= chunk_size else 0
            chunk_size_adj = end_pos - start_pos

            if chunk_size_adj < len(magic_pattern):
                break

            f.seek(start_pos, 0)
            data = f.read(chunk_size_adj)

            offs = data.rfind(magic_pattern)

            if offs != -1:
                cookie_pos = start_pos + offs
                break

            end_pos = start_pos + len(magic_pattern) - 1

            if start_pos == 0:
                break

        if cookie_pos != -1:
            break

    return cookie_pos


def python_magic_to_version(magic: bytes) -> tuple[int, int] | None:
    """Convert Python magic bytes to version tuple."""
    return PYC_MAGIC_TO_VERSION.get(magic[:4])

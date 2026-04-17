import struct
from pathlib import Path


PYC_MAGIC_NUMBERS = {
    (2, 5): b"\x03\x0d\x0d\x0a",
    (2, 6): b"\x03\x0d\x0d\x0a",
    (2, 7): b"\x42\x0d\x0d\x0a",
    (3, 0): b"\xeb\x0d\x0d\x0a",
    (3, 1): b"\xec\x0d\x0d\x0a",
    (3, 2): b"\xed\x0d\x0d\x0a",
    (3, 3): b"\xee\x0d\x0d\x0a",
    (3, 4): b"\xef\x0d\x0d\x0a",
    (3, 5): b"\xf0\x0d\x0d\x0a",
    (3, 6): b"\xf1\x0d\x0d\x0a",
    (3, 7): b"\x42\x0d\x0d\x0a",
    (3, 8): b"\x43\x0d\x0d\x0a",
    (3, 9): b"\x44\x0d\x0d\x0a",
    (3, 10): b"\x45\x0d\x0d\x0a",
    (3, 11): b"\x46\x0d\x0d\x0a",
    (3, 12): b"\x47\x0d\x0d\x0a",
    (3, 13): b"\x48\x0d\x0d\x0a",
    (3, 14): b"\x49\x0d\x0d\x0a",
}

# Inverse mapping: magic bytes -> version tuple
PYC_MAGIC_NUMBERS_INV = {v: k for k, v in PYC_MAGIC_NUMBERS.items()}


def get_pyc_header_size(python_version: tuple[int, int]) -> int:
    if python_version >= (3, 7):
        return 16
    elif python_version >= (3, 3):
        return 12
    else:
        return 8


def get_pyc_magic(python_version: tuple[int, int]) -> bytes:
    magic = PYC_MAGIC_NUMBERS.get(python_version)
    if magic is None:
        return b"\x42\x0d\x0d\x0a"
    return magic


def fix_pyc(pyc_path: Path, python_version: tuple[int, int] | None = None) -> bool:
    if not pyc_path.exists():
        return False

    try:
        with open(pyc_path, "rb") as f:
            data = f.read()

        if len(data) < 4:
            return False

        existing_magic = data[:4]

        if existing_magic in PYC_MAGIC_NUMBERS.values():
            return True

        if python_version is None:
            python_version = _detect_python_version(pyc_path)

        if python_version is None:
            python_version = (3, 10)

        header_size = get_pyc_header_size(python_version)

        if len(data) < header_size:
            return False

        magic = get_pyc_magic(python_version)

        if python_version >= (3, 7):
            flags = b"\x00\x00\x00\x00"
            timestamp = b"\x00\x00\x00\x00"
            size = b"\x00\x00\x00\x00"
        elif python_version >= (3, 3):
            flags = b"\x00\x00\x00\x00"
            timestamp = b"\x00\x00\x00\x00"
        else:
            timestamp = b"\x00\x00\x00\x00"
            size = b"\x00\x00\x00\x00"

        code_bytes = data[header_size:]

        fixed_data = magic
        if python_version >= (3, 7):
            fixed_data += flags + timestamp + size
        elif python_version >= (3, 3):
            fixed_data += flags + timestamp
        else:
            fixed_data += timestamp + size

        fixed_data += code_bytes

        with open(pyc_path, "wb") as f:
            f.write(fixed_data)

        return True
    except Exception:
        return False


def fix_directory(directory: Path, python_version: tuple[int, int] | None = None) -> int:
    count = 0
    for pyc_path in directory.rglob("*.pyc"):
        if fix_pyc(pyc_path, python_version):
            count += 1
    return count


def _detect_python_version(pyc_path: Path) -> tuple[int, int] | None:
    """Detect Python version from PYC magic bytes in file."""
    try:
        with open(pyc_path, "rb") as f:
            magic = f.read(4)
            return PYC_MAGIC_NUMBERS_INV.get(magic)
    except Exception:
        return None

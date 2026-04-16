import struct
from dataclasses import dataclass
from pathlib import Path

from anti_pyinstaller import logger


@dataclass
class PyInstallerInfo:
    is_pyinstaller: bool
    version: str
    python_version: tuple[int, int]
    platform: str
    is_encrypted: bool
    entry_point: str | None
    file_count: int


MAGIC_PATTERNS = [
    b"MEI\x0c\x0b\x0a\x0b\x0e",
    b"MEI\x0c\x0b\x0a\x0e",
    b"MEI\x0c\x0b\x0d\x0e",
    b"MEI\x0c\x0b\x0c\x0e",
    b"MEI\x0c\x0b\x0b\x0e",
]

PYINST20_COOKIE_SIZE = 24
PYINST21_COOKIE_SIZE = 88

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


def detect(path: Path) -> PyInstallerInfo | None:
    if not path.exists():
        logger.error(f"File not found: {path}")
        return None

    if not path.is_file():
        logger.error(f"Not a file: {path}")
        return None

    platform = _detect_platform(path)
    if platform == "unknown":
        logger.error("Unknown file format (not ELF or PE)")
        return None

    cookie_pos = _find_cookie(path)
    if cookie_pos == -1:
        logger.error("PyInstaller cookie not found")
        return None

    logger.debug(f"Cookie found at offset {cookie_pos}")

    try:
        with open(path, "rb") as f:
            f.seek(cookie_pos, 0)
            cookie_data = f.read(PYINST21_COOKIE_SIZE)

            magic = cookie_data[:8]
            if magic[:3] != b"MEI":
                logger.error("Invalid magic bytes")
                return None

            f.seek(cookie_pos + PYINST20_COOKIE_SIZE, 0)
            cookie_check = f.read(64)

            if b"python" in cookie_check.lower():
                (magic_bytes, lengthofPackage, toc_offset, tocLen, pyver, pylibname) = (
                    struct.unpack("!8sIIii64s", cookie_data)
                )
                pyinst_ver = "2.1+"
            else:
                (magic_bytes, lengthofPackage, toc_offset, tocLen, pyver) = struct.unpack(
                    "!8siiii", cookie_data[:24]
                )
                pyinst_ver = "2.0"

            if pyver == 0:
                logger.error("Invalid Python version in cookie")
                return None

            pymaj = pyver // 100 if pyver >= 100 else pyver // 10
            pymin = pyver % 100 if pyver >= 100 else pyver % 10

            f.seek(0, 2)
            file_size = f.tell()

            tail_bytes = (
                file_size
                - cookie_pos
                - (PYINST21_COOKIE_SIZE if pyinst_ver == "2.1+" else PYINST20_COOKIE_SIZE)
            )
            overlay_size = lengthofPackage + tail_bytes
            overlay_pos = file_size - overlay_size
            toc_pos = overlay_pos + toc_offset

            logger.debug(f"TOC at {toc_pos}, size {tocLen}")

            f.seek(toc_pos, 0)
            toc_data = f.read(tocLen)

            (file_count, entry_point, encrypted) = _parse_toc_info(toc_data, overlay_pos)

        return PyInstallerInfo(
            is_pyinstaller=True,
            version=pyinst_ver,
            python_version=(pymaj, pymin),
            platform=platform,
            is_encrypted=encrypted,
            entry_point=entry_point,
            file_count=file_count,
        )
    except Exception as e:
        logger.error(f"Failed to parse: {e}")
        logger.debug(f"Exception details: {type(e).__name__}: {e}")
        return None


def _detect_platform(path: Path) -> str:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\x7fELF":
            return "linux"
        elif magic.startswith(b"MZ"):
            return "windows"
    return "unknown"


def _find_cookie(path: Path) -> int:
    with open(path, "rb") as f:
        f.seek(0, 2)
        file_size = f.tell()

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
                    logger.debug(f"Found magic pattern at {cookie_pos}")
                    break

                end_pos = start_pos + len(magic_pattern) - 1

                if start_pos == 0:
                    break

            if cookie_pos != -1:
                break

    return cookie_pos


def _parse_toc_info(toc_data: bytes, overlay_pos: int) -> tuple[int, str | None, bool]:
    pos = 0
    file_count = 0
    entry_point = None
    encrypted = False

    fixed_part_size = struct.calcsize("!IIIBc")

    while pos < len(toc_data):
        if pos + 4 > len(toc_data):
            logger.debug(f"TOC parsing: truncated at pos {pos}")
            break

        entry_size = struct.unpack("!i", toc_data[pos : pos + 4])[0]

        if entry_size <= 0:
            logger.debug(f"TOC parsing: invalid entry size {entry_size} at pos {pos}")
            break

        if pos + entry_size > len(toc_data):
            logger.debug(f"TOC parsing: entry exceeds data at pos {pos}")
            break

        entry_bytes = toc_data[pos + 4 : pos + entry_size]

        if len(entry_bytes) < fixed_part_size:
            logger.debug(f"TOC: entry too small ({len(entry_bytes)} < {fixed_part_size})")
            pos += entry_size
            continue

        file_count += 1

        if b"_crypto_key" in entry_bytes:
            encrypted = True
            logger.debug("Found encryption key")

        name_bytes = entry_bytes[fixed_part_size:]
        name = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

        if name.endswith(".pyc") and entry_point is None:
            entry_point = name
            logger.debug(f"Entry point: {name}")

        pos += entry_size

    return file_count, entry_point, encrypted


def python_magic_to_version(magic: bytes) -> tuple[int, int] | None:
    return PYC_MAGIC_TO_VERSION.get(magic[:4])

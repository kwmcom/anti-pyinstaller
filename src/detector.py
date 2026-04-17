import struct
from dataclasses import dataclass
from pathlib import Path

from src import common, logger


@dataclass
class PyInstallerInfo:
    is_pyinstaller: bool
    version: str
    python_version: tuple[int, int]
    platform: str
    is_encrypted: bool
    entry_point: str | None
    file_count: int


@dataclass
class TOCEntry:
    name: str
    offset: int
    size: int
    compressed_size: int
    is_compressed: bool
    entry_type: bytes


def detect(path: Path) -> PyInstallerInfo | None:
    if not path.exists():
        logger.error(f"File not found: {path}")
        return None

    if not path.is_file():
        logger.error(f"Not a file: {path}")
        return None

    file_size = path.stat().st_size
    if file_size < 1024:
        logger.error(f"File too small: {file_size} bytes")
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
            cookie_data = f.read(common.PYINST21_COOKIE_SIZE)

            magic = cookie_data[:8]
            if magic[:3] != b"MEI":
                logger.error("Invalid magic bytes")
                return None

            f.seek(cookie_pos + common.PYINST20_COOKIE_SIZE, 0)
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

            if pyver == 0 or pyver > 1000:
                logger.error(f"Invalid Python version: {pyver}")
                return None

            if lengthofPackage < 0 or lengthofPackage > common.MAX_OVERLAY_SIZE:
                logger.error(f"Invalid overlay size: {lengthofPackage}")
                return None

            if toc_offset < 0 or tocLen < 0 or tocLen > file_size:
                logger.error(f"Invalid TOC: offset={toc_offset}, len={tocLen}")
                return None

            pymaj = pyver // 100 if pyver >= 100 else pyver // 10
            pymin = pyver % 100 if pyver >= 100 else pyver % 10

            f.seek(0, 2)
            file_size = f.tell()

            tail_bytes = (
                file_size
                - cookie_pos
                - (common.PYINST21_COOKIE_SIZE if pyinst_ver == "2.1+" else common.PYINST20_COOKIE_SIZE)
            )
            overlay_size = lengthofPackage + tail_bytes
            overlay_pos = file_size - overlay_size
            toc_pos = overlay_pos + toc_offset

            if toc_pos < 0 or toc_pos >= file_size:
                logger.error(f"Invalid TOC position: {toc_pos}")
                return None

            logger.debug(f"TOC at {toc_pos}, size {tocLen}")

            f.seek(toc_pos, 0)
            toc_data = f.read(tocLen)

            (entries, entry_point, encrypted, skipped) = _parse_toc_info(
                toc_data, overlay_pos, file_size
            )

            logger.info(f"TOC: {len(entries)} entries, {skipped} skipped")

            return PyInstallerInfo(
                is_pyinstaller=True,
                version=pyinst_ver,
                python_version=(pymaj, pymin),
                platform=platform,
                is_encrypted=encrypted,
                entry_point=entry_point,
                file_count=len(entries),
            )
    except Exception as e:
        logger.error(f"Failed to parse: {e}")
        logger.debug(f"Exception details: {type(e).__name__}: {e}")
        return None


def _detect_platform(path: Path) -> str:
    return common._detect_platform(path)


def _find_cookie(path: Path) -> int:
    return common._find_cookie(path)


def _parse_toc_info(
    toc_data: bytes, overlay_pos: int, file_size: int
) -> tuple[list[common.TOCEntry], str | None, bool, int]:
    entries = []
    entry_point = None
    encrypted = False
    skipped = 0
    pos = 0
    iterations = 0

    fixed_part_size = struct.calcsize("!IIIBc")

    while pos < len(toc_data):
        iterations += 1
        if iterations > common.MAX_TOC_ENTRIES:
            logger.warning(f"TOC: max iterations reached ({common.MAX_TOC_ENTRIES})")
            break

        if pos + 4 > len(toc_data):
            logger.debug(f"TOC: truncated at pos {pos}")
            break

        entry_size = struct.unpack("!i", toc_data[pos : pos + 4])[0]

        if entry_size <= 0 or entry_size > common.MAX_ENTRY_SIZE:
            logger.debug(f"TOC: invalid entry size {entry_size}")
            skipped += 1
            pos += 4
            continue

        if pos + entry_size > len(toc_data):
            logger.debug(f"TOC: entry exceeds data")
            skipped += 1
            break

        entry_bytes = toc_data[pos + 4 : pos + entry_size]

        if len(entry_bytes) < fixed_part_size:
            logger.debug(f"TOC: entry too small")
            skipped += 1
            pos += entry_size
            continue

        try:
            (entry_pos, cmprsd_size, uncmprsd_size, cmprs_flag, type_byte) = struct.unpack(
                "!IIIBc", entry_bytes[:fixed_part_size]
            )

            if entry_pos < 0 or cmprsd_size < 0 or uncmprsd_size < 0:
                logger.debug(f"TOC: negative values in entry")
                skipped += 1
                pos += entry_size
                continue

            name_bytes = entry_bytes[fixed_part_size:]
            try:
                name = name_bytes.rstrip(b"\x00").decode("utf-8")
            except UnicodeDecodeError:
                name = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

            name = name.lstrip("/")

            if not name:
                pos += entry_size
                continue

            name = name.replace("..", "__")

            abs_pos = overlay_pos + entry_pos
            if abs_pos < 0 or abs_pos >= file_size:
                logger.debug(f"TOC: invalid offset {abs_pos}")
                skipped += 1
                pos += entry_size
                continue

            entry = common.TOCEntry(
                name=name,
                offset=abs_pos,
                size=uncmprsd_size,
                compressed_size=cmprsd_size,
                is_compressed=cmprs_flag == 1,
                entry_type=type_byte,
            )
            entries.append(entry)

            if b"_crypto_key" in entry_bytes:
                encrypted = True
                logger.debug("Found encryption key")

            if type_byte == b"s" and entry_point is None:
                entry_point = name
                logger.debug(f"Entry point: {name}")

        except Exception as e:
            logger.debug(f"TOC parse error: {e}")
            skipped += 1

        pos += entry_size

    return entries, entry_point, encrypted, skipped


def python_magic_to_version(magic: bytes) -> tuple[int, int] | None:
    return common.PYC_MAGIC_TO_VERSION.get(magic[:4])

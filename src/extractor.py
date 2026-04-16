import marshal
import os
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from src import logger


@dataclass
class ArchiveInfo:
    pyinstaller_ver: str
    python_ver: tuple[int, int]
    file_count: int
    entry_point: str | None
    encrypted: bool = False


@dataclass
class ExtractionResult:
    success: bool
    output_dir: Path
    info: ArchiveInfo | None
    message: str


@dataclass
class TOCEntry:
    name: str
    offset: int
    size: int
    compressed_size: int
    is_compressed: bool
    entry_type: bytes


MAGIC_PATTERNS = [
    b"MEI\x0c\x0b\x0a\x0b\x0e",
    b"MEI\x0c\x0b\x0a\x0e",
    b"MEI\x0c\x0b\x0d\x0e",
    b"MEI\x0c\x0b\x0c\x0e",
    b"MEI\x0c\x0b\x0b\x0e",
]

PYINST20_COOKIE_SIZE = 24
PYINST21_COOKIE_SIZE = 88

MAX_TOC_ENTRIES = 10000
MAX_ENTRY_SIZE = 10 * 1024 * 1024
MAX_OVERLAY_SIZE = 500 * 1024 * 1024


def extract(input_file: Path, output_dir: Path | None = None) -> ExtractionResult:
    if not input_file.exists():
        logger.error(f"File not found: {input_file}")
        return ExtractionResult(False, Path(""), None, "File not found")

    if not input_file.is_file():
        logger.error(f"Not a file: {input_file}")
        return ExtractionResult(False, Path(""), None, "Not a file")

    file_size = input_file.stat().st_size
    if file_size < 1024:
        logger.error(f"File too small: {file_size} bytes")
        return ExtractionResult(False, Path(""), None, "File too small")

    if file_size > MAX_OVERLAY_SIZE * 2:
        logger.error(f"File too large: {file_size} bytes (max {MAX_OVERLAY_SIZE * 2})")
        return ExtractionResult(False, Path(""), None, "File too large")

    platform = _detect_platform(input_file)
    if platform == "unknown":
        logger.error("Unknown file format (not ELF or PE)")
        return ExtractionResult(False, Path(""), None, "Unknown file format")

    if output_dir is None:
        output_dir = input_file.parent / f"{input_file.stem}_extracted"

    if output_dir.exists() and any(output_dir.iterdir()):
        logger.warning(f"Output directory exists and is not empty: {output_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    logger.debug(f"Extracting to: {output_dir}")

    try:
        result = _extract_archive(input_file, output_dir)
        return result
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        logger.debug(f"Exception: {type(e).__name__}: {e}")
        return ExtractionResult(False, output_dir, None, str(e))


def _detect_platform(path: Path) -> str:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\x7fELF":
            return "linux"
        elif magic.startswith(b"MZ"):
            return "windows"
    return "unknown"


def _find_cookie(f, file_size: int) -> int:
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
                logger.debug(f"Found cookie at {cookie_pos}")
                break

            end_pos = start_pos + len(magic_pattern) - 1

            if start_pos == 0:
                break

        if cookie_pos != -1:
            break

    return cookie_pos


def _extract_archive(input_path: Path, output_dir: Path) -> ExtractionResult:
    with open(input_path, "rb") as f:
        f.seek(0, 2)
        file_size = f.tell()

        cookie_pos = _find_cookie(f, file_size)
        if cookie_pos == -1:
            logger.error("PyInstaller cookie not found")
            return ExtractionResult(False, output_dir, None, "Cookie not found")

        f.seek(cookie_pos, 0)
        cookie_data = f.read(PYINST21_COOKIE_SIZE)

        magic = cookie_data[:8]
        if magic[:3] != b"MEI":
            logger.error("Invalid magic bytes")
            return ExtractionResult(False, output_dir, None, "Invalid magic")

        f.seek(cookie_pos + PYINST20_COOKIE_SIZE, 0)
        cookie_check = f.read(64)

        if b"python" in cookie_check.lower():
            (magic_bytes, lengthofPackage, toc_offset, tocLen, pyver, pylibname) = struct.unpack(
                "!8sIIii64s", cookie_data
            )
            cookie_size = PYINST21_COOKIE_SIZE
            pyinst_ver = "2.1+"
        else:
            (magic_bytes, lengthofPackage, toc_offset, tocLen, pyver) = struct.unpack(
                "!8siiii", cookie_data[:24]
            )
            cookie_size = PYINST20_COOKIE_SIZE
            pyinst_ver = "2.0"

        if pyver == 0 or pyver > 1000:
            logger.error(f"Invalid Python version: {pyver}")
            return ExtractionResult(False, output_dir, None, "Invalid Python version")

        if lengthofPackage < 0 or lengthofPackage > MAX_OVERLAY_SIZE:
            logger.error(f"Invalid overlay size: {lengthofPackage}")
            return ExtractionResult(False, output_dir, None, "Invalid overlay size")

        if toc_offset < 0 or tocLen < 0 or tocLen > file_size:
            logger.error(f"Invalid TOC: offset={toc_offset}, len={tocLen}")
            return ExtractionResult(False, output_dir, None, "Invalid TOC")

        pymaj = pyver // 100 if pyver >= 100 else pyver // 10
        pymin = pyver % 100 if pyver >= 100 else pyver % 10

        logger.debug(f"PyInstaller {pyinst_ver}, Python {pymaj}.{pymin}")

        tail_bytes = file_size - cookie_pos - cookie_size
        overlay_size = lengthofPackage + tail_bytes
        overlay_pos = file_size - overlay_size
        toc_pos = overlay_pos + toc_offset

        if toc_pos < 0 or toc_pos >= file_size:
            logger.error(f"Invalid TOC position: {toc_pos}")
            return ExtractionResult(False, output_dir, None, "Invalid TOC position")

        f.seek(toc_pos, 0)
        toc_data = f.read(tocLen)

        entries, entry_point, skipped = _parse_toc_entries(toc_data, overlay_pos, file_size)

        logger.info(f"TOC: {len(entries)} entries, {skipped} skipped")

        pyc_magic = None
        encrypted = False

        for entry in entries:
            if entry.entry_type == b"M" and pyc_magic is None:
                if _has_pyc_header(entry, f):
                    data = _read_entry_data(f, entry)
                    if data and len(data) >= 4:
                        pyc_magic = data[:4]

            if entry.name.endswith("_crypto_key"):
                encrypted = True
                logger.debug("Found encryption key")

        written = 0
        for entry in entries:
            if _write_entry(f, entry, output_dir, pyc_magic):
                written += 1

        logger.debug(f"Wrote {written} files")

        if encrypted:
            logger.warning("Encrypted archive - some files may not extract")

        _extract_pyz_archives(output_dir, pyc_magic)

        info = ArchiveInfo(
            pyinstaller_ver=pyinst_ver,
            python_ver=(pymaj, pymin),
            file_count=len(entries),
            entry_point=entry_point,
            encrypted=encrypted,
        )

        return ExtractionResult(True, output_dir, info, f"Extracted {len(entries)} files")


def _parse_toc_entries(
    toc_data: bytes, overlay_pos: int, file_size: int
) -> tuple[list[TOCEntry], str | None, int]:
    entries = []
    entry_point = None
    skipped = 0
    pos = 0
    iterations = 0

    fixed_part_size = struct.calcsize("!IIIBc")

    while pos < len(toc_data):
        iterations += 1
        if iterations > MAX_TOC_ENTRIES:
            logger.warning(f"TOC: max iterations reached ({MAX_TOC_ENTRIES})")
            break

        if pos + 4 > len(toc_data):
            logger.debug(f"TOC: truncated at pos {pos}")
            break

        entry_size = struct.unpack("!i", toc_data[pos : pos + 4])[0]

        if entry_size <= 0 or entry_size > MAX_ENTRY_SIZE:
            logger.debug(f"TOC: invalid entry size {entry_size}, skipping")
            skipped += 1
            pos += 4
            continue

        if pos + entry_size > len(toc_data):
            logger.debug(f"TOC: entry exceeds buffer, skipping")
            skipped += 1
            break

        entry_bytes = toc_data[pos + 4 : pos + entry_size]

        if len(entry_bytes) < fixed_part_size:
            logger.debug(f"TOC: entry too small, skipping")
            skipped += 1
            pos += entry_size
            continue

        try:
            (entry_pos, cmprsd_size, uncmprsd_size, cmprs_flag, type_byte) = struct.unpack(
                "!IIIBc", entry_bytes[:fixed_part_size]
            )

            if entry_pos < 0 or cmprsd_size < 0 or uncmprsd_size < 0:
                logger.debug(f"TOC: negative values in entry, skipping")
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

            name = _sanitize_path(name)

            abs_pos = overlay_pos + entry_pos
            if abs_pos < 0 or abs_pos >= file_size:
                logger.debug(f"TOC: invalid offset {abs_pos}, skipping entry")
                skipped += 1
                pos += entry_size
                continue

            entry = TOCEntry(
                name=name,
                offset=abs_pos,
                size=uncmprsd_size,
                compressed_size=cmprsd_size,
                is_compressed=cmprs_flag == 1,
                entry_type=type_byte,
            )
            entries.append(entry)

            if type_byte == b"s" and entry_point is None:
                entry_point = name + ".pyc"
                logger.debug(f"Entry point: {entry_point}")

        except Exception as e:
            logger.debug(f"TOC parse error: {e}")
            skipped += 1
            pass

        pos += entry_size

    return entries, entry_point, skipped


def _sanitize_path(name: str) -> str:
    name = name.replace("..", "__")
    name = name.lstrip("/")
    return name


def _has_pyc_header(entry: TOCEntry, f) -> bool:
    f.seek(entry.offset, 0)
    data = f.read(min(entry.compressed_size, 16))
    if len(data) >= 4:
        if data[2:4] == b"\r\n":
            return True
    return False


def _read_entry_data(f, entry: TOCEntry):
    f.seek(entry.offset, 0)
    data = f.read(entry.compressed_size)

    if entry.is_compressed:
        try:
            data = zlib.decompress(data)
        except zlib.error as e:
            logger.debug(f"Decompress failed for {entry.name}: {e}")
            return None

    return data


def _write_entry(f, entry: TOCEntry, output_dir: Path, pyc_magic: bytes | None = None) -> bool:
    data = _read_entry_data(f, entry)
    if data is None:
        return False

    name = entry.name

    if entry.entry_type == b"s":
        name = name + ".pyc"
        _write_pyc_with_header(output_dir / name, data, pyc_magic)
        return True

    out_path = output_dir / name
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        out_path.write_bytes(data)
        return True
    except Exception as e:
        logger.debug(f"Write failed for {name}: {e}")
        return False


def _extract_pyz_archives(output_dir: Path, pyc_magic: bytes | None):
    pyz_files = list(output_dir.rglob("*.pyz"))
    logger.debug(f"Found {len(pyz_files)} PYZ files")

    for pyz_path in pyz_files:
        _extract_pyz(pyz_path, pyc_magic)


def _extract_pyz(pyz_path: Path, pyc_magic: bytes | None):
    try:
        with open(pyz_path, "rb") as f:
            magic = f.read(4)
            if magic != b"PYZ\x00":
                return

            pyz_pyc_magic = f.read(4)

            if pyc_magic is None:
                pyc_magic = pyz_pyc_magic

            toc_offset = struct.unpack("!i", f.read(4))[0]
            f.seek(toc_offset, 0)

            try:
                tbl = marshal.load(f)
            except Exception as e:
                logger.debug(f"PYZ marshal failed: {e}")
                return

            if not isinstance(tbl, (list, dict)):
                return

            out_dir = pyz_path.with_suffix("")
            out_dir.mkdir(exist_ok=True)

            if isinstance(tbl, list):
                entries = tbl
            else:
                entries = list(tbl.items())

            written = 0
            for item in entries:
                if isinstance(item, tuple) and len(item) >= 2:
                    name = item[0]
                    data_tuple = item[1]

                    if not isinstance(data_tuple, tuple) or len(data_tuple) < 3:
                        continue

                    is_pkg = data_tuple[0]
                    offset = data_tuple[1]

                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")

                    name = _sanitize_path(name.replace(".", os.path.sep))

                    if is_pkg == 1:
                        file_path = out_dir / name / "__init__.pyc"
                    else:
                        file_path = out_dir / (name + ".pyc")

                    file_path.parent.mkdir(parents=True, exist_ok=True)

                    try:
                        f.seek(offset, 0)
                        data = f.read()
                        uncompressed = zlib.decompress(data)
                        _write_pyc(file_path, uncompressed, pyc_magic)
                        written += 1
                    except Exception as e:
                        logger.debug(f"PYZ entry failed ({name}): {e}")

            logger.debug(f"PYZ: wrote {written} files")

    except Exception as e:
        logger.debug(f"PYZ extraction failed: {e}")


def _write_pyc(path: Path, code_bytes: bytes, pyc_magic: bytes | None):
    if pyc_magic is None:
        pyc_magic = b"\x42\x0d\x0d\x0a"

    with open(path, "wb") as f:
        f.write(pyc_magic)
        f.write(b"\x00\x00\x00\x00")
        f.write(b"\x00\x00\x00\x00")
        f.write(b"\x00\x00\x00\x00")
        f.write(code_bytes)


def _write_pyc_with_header(path: Path, data: bytes, pyc_magic: bytes | None):
    if pyc_magic is None:
        pyc_magic = b"\x42\x0d\x0d\x0a"

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "wb") as f:
        f.write(pyc_magic)
        f.write(b"\x00\x00\x00\x00")
        f.write(b"\x00\x00\x00\x00")
        f.write(b"\x00\x00\x00\x00")
        f.write(data)

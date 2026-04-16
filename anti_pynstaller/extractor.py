import marshal
import os
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path


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


MAGIC_PATTERNS = [
    b"MEI\x0c\x0b\x0a\x0b\x0e",
    b"MEI\x0c\x0b\x0a\x0e",
    b"MEI\x0c\x0b\x0d\x0e",
    b"MEI\x0c\x0b\x0c\x0e",
    b"MEI\x0c\x0b\x0b\x0e",
]

PYINST20_COOKIE_SIZE = 24
PYINST21_COOKIE_SIZE = 88


class CTOCEntry:
    def __init__(
        self,
        position: int,
        cmprsd_size: int,
        uncmprsd_size: int,
        cmprs_flag: int,
        type_byte: bytes,
        name: str,
    ):
        self.position = position
        self.cmprsd_size = cmprsd_size
        self.uncmprsd_size = uncmprsd_size
        self.cmprs_flag = cmprs_flag
        self.type_byte = type_byte
        self.name = name


def detect(input_file: Path) -> ArchiveInfo | None:
    with open(input_file, "rb") as f:
        f.seek(0, 2)
        file_size = f.tell()

        cookie_pos = _find_cookie(f, file_size)
        if cookie_pos == -1:
            return None

        cookie_data = f.read(PYINST21_COOKIE_SIZE)
        if len(cookie_data) < PYINST20_COOKIE_SIZE:
            return None

        magic = cookie_data[:8]
        if magic[:3] != b"MEI":
            return None

        f.seek(cookie_pos + PYINST20_COOKIE_SIZE, 0)
        cookie_check = f.read(64)

        if b"python" in cookie_check.lower():
            (magic_bytes, lengthofPackage, toc_offset, tocLen, pyver, pylibname) = struct.unpack(
                "!8sIIii64s", cookie_data
            )
            pyinst_ver = "2.1+"
        else:
            (magic_bytes, lengthofPackage, toc_offset, tocLen, pyver) = struct.unpack(
                "!8siiii", cookie_data[:24]
            )
            pyinst_ver = "2.0"

        if pyver == 0:
            return None

        pymaj = pyver // 100 if pyver >= 100 else pyver // 10
        pymin = pyver % 100 if pyver >= 100 else pyver % 10
        python_ver = (pymaj, pymin)

        tail_bytes = (
            file_size
            - cookie_pos
            - (PYINST21_COOKIE_SIZE if pyinst_ver == "2.1+" else PYINST20_COOKIE_SIZE)
        )
        overlay_size = lengthofPackage + tail_bytes
        overlay_pos = file_size - overlay_size

        toc_pos = overlay_pos + toc_offset

        f.seek(toc_pos, 0)
        toc_data = f.read(tocLen)

        entries, entry_point = _parse_toc_entries(toc_data, overlay_pos)
        file_count = len(entries)

        return ArchiveInfo(
            pyinstaller_ver=pyinst_ver,
            python_ver=python_ver,
            file_count=file_count,
            entry_point=entry_point,
        )


def extract(input_file: Path, output_dir: Path | None = None) -> ExtractionResult:
    if not input_file.exists():
        return ExtractionResult(False, Path(""), None, "File not found: " + str(input_file))

    platform = _detect_platform(input_file)
    if platform == "unknown":
        return ExtractionResult(False, Path(""), None, "Unknown file format")

    if output_dir is None:
        output_dir = input_file.parent / f"{input_file.stem}_extracted"

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = _extract_archive(input_file, output_dir)
        return result
    except Exception as e:
        return ExtractionResult(False, output_dir, None, f"Extraction failed: {e}")


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
            return ExtractionResult(
                False, output_dir, None, "Cookie not found: not a PyInstaller archive"
            )

        f.seek(cookie_pos, 0)
        cookie_data = f.read(PYINST21_COOKIE_SIZE)

        magic = cookie_data[:8]
        if magic[:3] != b"MEI":
            return ExtractionResult(False, output_dir, None, "Invalid magic bytes")

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

        if pyver == 0:
            return ExtractionResult(False, output_dir, None, "Invalid Python version")

        pymaj = pyver // 100 if pyver >= 100 else pyver // 10
        pymin = pyver % 100 if pyver >= 100 else pyver % 10

        tail_bytes = file_size - cookie_pos - cookie_size
        overlay_size = lengthofPackage + tail_bytes
        overlay_pos = file_size - overlay_size
        toc_pos = overlay_pos + toc_offset

        f.seek(toc_pos, 0)
        toc_data = f.read(tocLen)

        entries, entry_point = _parse_toc_entries(toc_data, overlay_pos)

        pyc_magic = None
        encrypted = False

        # First pass: find pyc magic from PYPACKAGE entries
        for entry in entries:
            if entry.type_byte == b"M" and pyc_magic is None:
                if _has_pyc_header(entry, f):
                    data = _read_entry_data(f, entry)
                    if data and len(data) >= 4:
                        pyc_magic = data[:4]

            if entry.name.endswith("_crypto_key"):
                encrypted = True

        # Second pass: write entries
        for entry in entries:
            _write_entry(f, entry, output_dir, pyc_magic)

        if encrypted:
            print("[!] Encrypted archive detected - extraction may be incomplete")

        _extract_pyz_archives(output_dir, pyc_magic)

        info = ArchiveInfo(
            pyinstaller_ver=pyinst_ver,
            python_ver=(pymaj, pymin),
            file_count=len(entries),
            entry_point=entry_point,
            encrypted=encrypted,
        )

        return ExtractionResult(True, output_dir, info, f"Extracted {len(entries)} files")


def _parse_toc_entries(toc_data: bytes, overlay_pos: int) -> tuple[list[CTOCEntry], str | None]:
    entries = []
    entry_point = None
    pos = 0

    while pos < len(toc_data):
        if pos + 4 > len(toc_data):
            break

        entry_size = struct.unpack("!i", toc_data[pos : pos + 4])[0]
        if entry_size <= 0 or pos + entry_size > len(toc_data):
            break

        entry_bytes = toc_data[pos + 4 : pos + entry_size]
        if len(entry_bytes) < 17:
            pos += entry_size
            continue

        try:
            fixed_part_size = struct.calcsize("!IIIBc")
            if len(entry_bytes) < fixed_part_size:
                pos += entry_size
                continue

            (entry_pos, cmprsd_size, uncmprsd_size, cmprs_flag, type_byte) = struct.unpack(
                "!IIIBc", entry_bytes[:fixed_part_size]
            )

            name_bytes = entry_bytes[fixed_part_size:]
            name = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

            name = name.lstrip("/")

            if not name:
                continue

            entry = CTOCEntry(
                position=overlay_pos + entry_pos,
                cmprsd_size=cmprsd_size,
                uncmprsd_size=uncmprsd_size,
                cmprs_flag=cmprs_flag,
                type_byte=type_byte,
                name=name,
            )
            entries.append(entry)

            # Type 's' (PYSOURCE) is the entry point script
            if type_byte == b"s" and entry_point is None:
                entry_point = name + ".pyc"

        except Exception:
            pass

        pos += entry_size

    return entries, entry_point


def _has_pyc_header(entry: CTOCEntry, f) -> bool:
    f.seek(entry.position, 0)
    data = f.read(min(entry.cmprsd_size, 16))
    if len(data) >= 4:
        if data[2:4] == b"\r\n":
            return True
    return False


def _read_entry_data(f, entry: CTOCEntry):
    f.seek(entry.position, 0)
    data = f.read(entry.cmprsd_size)

    if entry.cmprs_flag == 1:
        try:
            data = zlib.decompress(data)
        except zlib.error:
            return None

    return data


def _write_entry(f, entry: CTOCEntry, output_dir: Path, pyc_magic: bytes | None = None):
    data = _read_entry_data(f, entry)
    if data is None:
        return

    name = entry.name

    # Type 's' is PYSOURCE - write as .pyc file (raw code object needs header)
    if entry.type_byte == b"s":
        name = name + ".pyc"
        _write_pyc_with_header(output_dir / name, data, pyc_magic)
        return

    out_path = output_dir / name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)


def _extract_pyz_archives(output_dir: Path, pyc_magic: bytes | None):
    for pyz_path in output_dir.rglob("*.pyz"):
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
            except Exception:
                return

            if not isinstance(tbl, (list, dict)):
                return

            out_dir = pyz_path.with_suffix("")
            out_dir.mkdir(exist_ok=True)

            if isinstance(tbl, list):
                entries = tbl
            else:
                entries = list(tbl.items())

            for item in entries:
                if isinstance(item, tuple) and len(item) >= 2:
                    name = item[0]
                    data_tuple = item[1]

                    if not isinstance(data_tuple, tuple) or len(data_tuple) < 3:
                        continue

                    is_pkg = data_tuple[0]
                    offset = data_tuple[1]
                    length = data_tuple[2]

                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")

                    name = name.replace(".", os.path.sep)

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
                    except Exception:
                        pass
    except Exception:
        pass


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

import dis
import marshal
import sys
import types
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DisasmResult:
    success: bool
    output_path: Path | None
    message: str


PYC_HEADER_SIZES = {
    (2, 5): 8,
    (2, 6): 8,
    (2, 7): 8,
    (3, 0): 8,
    (3, 1): 8,
    (3, 2): 8,
    (3, 3): 12,
    (3, 4): 12,
    (3, 5): 12,
    (3, 6): 12,
    (3, 7): 16,
    (3, 8): 16,
    (3, 9): 16,
    (3, 10): 16,
    (3, 11): 16,
    (3, 12): 16,
    (3, 13): 16,
    (3, 14): 16,
}


def get_pyc_header_size(python_version: tuple[int, int] | None = None) -> int:
    if python_version is None:
        return 16
    return PYC_HEADER_SIZES.get(python_version, 16)


def disassemble(pyc_path: Path, output_path: Path | None = None) -> DisasmResult:
    if not pyc_path.exists():
        return DisasmResult(False, None, "File not found")

    try:
        with open(pyc_path, "rb") as f:
            magic = f.read(4)

            header_size = _detect_header_size(f)

            f.seek(0)
            f.read(header_size)
            code_bytes = f.read()

            try:
                code_obj = marshal.loads(code_bytes)
            except Exception as e:
                return DisasmResult(False, None, f"Failed to unmarshal: {e}")

            if not isinstance(code_obj, types.CodeType):
                return DisasmResult(False, None, "Not a valid code object")

        output = _disassemble_code(code_obj)

        if output_path is None:
            output_path = pyc_path.with_suffix(".py")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output)

        return DisasmResult(True, output_path, "Disassembly complete")
    except Exception as e:
        return DisasmResult(False, None, str(e))


def disassemble_directory(directory: Path) -> int:
    count = 0
    for pyc_path in directory.rglob("*.pyc"):
        result = disassemble(pyc_path)
        if result.success:
            count += 1
    return count


def _detect_header_size(f) -> int:
    f.seek(0, 2)
    file_size = f.tell()

    if file_size < 16:
        return 8

    f.seek(0, 0)
    magic = f.read(4)

    header_size = 16
    if magic in (b"\x42\x0d\x0d\x0a", b"\x43\x0d\x0d\x0a", b"\x44\x0d\x0d\x0a"):
        header_size = 16
    elif magic in (
        b"\xee\x0d\x0d\x0a",
        b"\xef\x0d\x0d\x0a",
        b"\xf0\x0d\x0d\x0a",
        b"\xf1\x0d\x0d\x0a",
    ):
        header_size = 12
    elif magic in (b"\xeb\x0d\x0d\x0a", b"\xec\x0d\x0d\x0a", b"\xed\x0d\x0d\x0a"):
        header_size = 8
    else:
        if file_size > 16:
            header_size = 16

    return header_size


def _disassemble_code(code: types.CodeType, indent: int = 0) -> str:
    output = []
    prefix = "    " * indent

    output.append(f"{prefix}# Source: {code.co_filename}")
    output.append(f"{prefix}# Line: {code.co_firstlineno}")
    output.append("")

    if code.co_name != "<module>":
        args = _format_args(code.co_varnames, code.co_argcount, code.co_kwonlyargcount)
        output.append(f"{prefix}def {code.co_name}{args}:")

    output.append(f"{prefix}    # Disassembly:")

    for instr in dis.get_instructions(code):
        output.append(f"{prefix}    {instr.offset:>4} {instr.opname:<16} {instr.argrepr}")

    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            output.append("")
            output.append(_disassemble_code(const, indent))

    return "\n".join(output)


def _format_args(varnames: tuple, argcount: int, kwonly: int) -> str:
    args = list(varnames[:argcount])
    if kwonly:
        args.append("*")
        args.extend(varnames[argcount : argcount + kwonly])
    if not args:
        return "()"
    return f"({', '.join(args)})"


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m anti_pynstaller.disasm <pyc_file>")
        sys.exit(1)

    pyc_path = Path(sys.argv[1])
    result = disassemble(pyc_path)

    if result.success:
        print(f"Disassembled to: {result.output_path}")
    else:
        print(f"Error: {result.message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

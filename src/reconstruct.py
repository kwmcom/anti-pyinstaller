import dis
import marshal
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ReconstructResult:
    success: bool
    output_path: Path | None
    message: str


def reconstruct(pyc_path: Path, output_path: Path | None = None) -> ReconstructResult:
    if not pyc_path.exists():
        return ReconstructResult(False, None, "File not found")

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
                return ReconstructResult(False, None, f"Failed to unmarshal: {e}")

            if not isinstance(code_obj, types.CodeType):
                return ReconstructResult(False, None, "Not a valid code object")

        try:
            output = _reconstruct_code(code_obj)
        except Exception as e:
            return ReconstructResult(False, None, f"Reconstruction failed: {e}")

        if output_path is None:
            output_path = pyc_path.with_suffix(".py")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output)

        return ReconstructResult(True, output_path, "Reconstruction complete")
    except Exception as e:
        return ReconstructResult(False, None, str(e))


def reconstruct_directory(directory: Path) -> int:
    count = 0
    for pyc_path in directory.rglob("*.pyc"):
        result = reconstruct(pyc_path)
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
        header_size = 16 if file_size > 16 else 8

    return header_size


def _reconstruct_code(code: types.CodeType, indent: int = 0) -> str:
    output = []
    prefix = "    " * indent

    is_main = code.co_name == "<module>"

    if not is_main:
        args = list(code.co_varnames[: code.co_argcount])
        kwonly = code.co_kwonlyargcount
        if kwonly:
            args.append("*")
            args.extend(code.co_varnames[code.co_argcount : code.co_argcount + kwonly])
        args_str = ", ".join(args) if args else ""
        output.append(f"def {code.co_name}({args_str}):")

    instructions = list(dis.get_instructions(code))
    lines = _process_instructions(instructions, code)

    for line in lines:
        output.append(f"{prefix}{line}")

    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name not in ("<module>", "<lambda>", "__init__"):
                output.append("")
                output.append(_reconstruct_code(const, indent))

    return "\n".join(output)


def _process_instructions(instructions: list, code: types.CodeType) -> list[str]:
    lines = []
    stack = []
    i = 0

    skip_ops = {
        "RESUME",
        "NOP",
        "NOT_TAKEN",
        "CACHE",
        "PUSH_NULL",
        "COPY_FREE_VARS",
        "LOAD_LOCALS",
        "MAKE_CELL",
        "LOAD_FAST_BORROW",
        "SET_FUNCTION_ATTRIBUTE",
        "STORE_DEREF",
        "FREEZE_VALUE",
        "SETUP_FINALLY",
        "SETUP_WITH",
        "WITH_EXCEPT_START",
        "END_FINALLY",
        "POP_EXCEPT",
        "RERAISE",
        "LOAD_BUILD_CLASS",
        "CALL_INTRINSIC_1",
        "CALL_INTRINSIC_2",
    }

    while i < len(instructions):
        instr = instructions[i]
        op = instr.opname
        arg = instr.arg
        arg_repr = instr.argrepr

        if op in skip_ops:
            i += 1
            continue

        if op == "LOAD_CONST":
            if arg_repr not in ("None", "Ellipsis", "True", "False"):
                stack.append(_format_arg(arg_repr, code))
        elif op == "LOAD_FAST":
            if arg is not None and arg < len(code.co_varnames):
                name = code.co_varnames[arg]
            else:
                name = f"local_{arg}" if arg is not None else "local"
            stack.append(name)
        elif op == "LOAD_NAME":
            if arg is not None and arg < len(code.co_names):
                name = code.co_names[arg]
            else:
                name = f"name_{arg}" if arg is not None else "name"
            stack.append(name)
        elif op == "LOAD_GLOBAL":
            if arg is not None and (arg & 0x08):
                idx = arg & 0x0F
                if idx < len(code.co_names):
                    name = f"__builtins__.{code.co_names[idx]}"
                else:
                    name = f"__builtins__.global_{idx}"
            elif arg is not None and arg < len(code.co_names):
                name = code.co_names[arg]
            else:
                name = f"global_{arg}" if arg is not None else "global"
            stack.append(name)
        elif op == "STORE_FAST":
            if stack and arg is not None:
                val = stack.pop()
                if arg < len(code.co_varnames):
                    name = code.co_varnames[arg]
                else:
                    name = f"local_{arg}"
                lines.append(f"{name} = {val}")
        elif op == "STORE_NAME":
            if stack and arg is not None:
                val = stack.pop()
                if arg < len(code.co_names):
                    name = code.co_names[arg]
                else:
                    name = f"name_{arg}"
                lines.append(f"{name} = {val}")
        elif op == "STORE_GLOBAL":
            if stack and arg is not None:
                val = stack.pop()
                if arg < len(code.co_names):
                    name = code.co_names[arg]
                else:
                    name = f"global_{arg}"
                lines.append(f"global {name}")
                lines.append(f"{name} = {val}")
        elif op == "CALL":
            func = stack.pop() if stack else "?"
            args = []
            for _ in range(arg):
                if stack:
                    args.insert(0, stack.pop())
            if args:
                lines.append(f"{func}({', '.join(args)})")
            else:
                lines.append(f"{func}()")
            stack.clear()
        elif op == "RETURN_VALUE":
            if stack:
                val = stack.pop()
                lines.append(f"return {val}")
            else:
                lines.append("return")
        elif op == "PRINT":
            if stack:
                val = stack.pop()
                lines.append(f"print({val})")
        elif op == "POP_JUMP_IF_FALSE":
            if stack:
                cond = stack.pop()
                lines.append(f"if {cond}:")
                lines.append("    pass")
        elif op == "POP_JUMP_IF_TRUE":
            if stack:
                cond = stack.pop()
                lines.append(f"if not {cond}:")
                lines.append("    pass")
        elif op == "FOR_ITER":
            lines.append("    # for loop")
        elif op == "GET_ITER":
            pass
        elif op == "JUMP_FORWARD":
            pass
        elif op == "JUMP_ABSOLUTE":
            pass
        elif op == "BUILD_LIST":
            count = arg if arg else 0
            items = stack[-count:] if count <= len(stack) else stack
            stack = stack[:-count] if count <= len(stack) else []
            if items:
                lines.append(f"[{', '.join(items)}]")
                stack.append(f"[{', '.join(items)}]")
        elif op == "BUILD_TUPLE":
            count = arg if arg else 0
            items = stack[-count:] if count <= len(stack) else stack
            stack = stack[:-count] if count <= len(stack) else []
            if items:
                lines.append(f"({', '.join(items)},)")
                stack.append(f"({', '.join(items)},)")
        elif op == "BUILD_DICT":
            lines.append("{}")
            stack.append("{}")
        elif op == "BINARY_OP":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                op_str = arg_repr if arg_repr else "+"
                result = f"({a} {op_str} {b})"
                stack.append(result)
        elif op == "COMPARE_OP":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                cmp = arg_repr if arg_repr else "=="
                stack.append(f"({a} {cmp} {b})")
        elif op == "MAKE_FUNCTION":
            lines.append("# function defined")
        elif op == "IMPORT_NAME":
            name = code.co_names[arg] if arg < len(code.co_names) else "module"
            lines.append(f"import {name}")
        elif op == "IMPORT_FROM":
            pass
        elif op == "LOAD_ATTR":
            if stack:
                attr = code.co_names[arg] if arg < len(code.co_names) else "attr"
                obj = stack.pop() if stack else "self"
                stack.append(f"{obj}.{attr}")
        elif op == "STORE_ATTR":
            if len(stack) >= 2:
                val = stack.pop()
                attr = code.co_names[arg] if arg < len(code.co_names) else "attr"
                obj = stack.pop() if stack else "self"
                lines.append(f"{obj}.{attr} = {val}")
        elif op == "UNARY_NEGATIVE":
            if stack:
                val = stack.pop()
                stack.append(f"-{val}")
        elif op == "UNARY_POSITIVE":
            if stack:
                val = stack.pop()
                stack.append(f"+{val}")
        elif op == "UNARY_NOT":
            if stack:
                val = stack.pop()
                stack.append(f"not {val}")
        elif op == "IS_OP":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                negate = "not " if arg else ""
                stack.append(f"({negate}a is b)")
        elif op == "CONTAINS_OP":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                negate = "not " if arg else ""
                stack.append(f"({negate}a in b)")
        else:
            lines.append(f"# {op} {arg_repr}")

        i += 1

    return lines


def _format_arg(arg: str, code: types.CodeType) -> str:
    if arg is None:
        return "None"

    arg_str = str(arg)

    if arg_str.startswith("<code object"):
        return "# code"
    elif arg_str.startswith("<function"):
        return "# func"
    elif arg_str.startswith("<class"):
        return "# class"
    elif arg_str.startswith("'"):
        return arg_str
    elif arg_str.isdigit():
        return arg_str

    return arg_str


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.reconstruct <pyc_file>")
        sys.exit(1)

    pyc_path = Path(sys.argv[1])
    result = reconstruct(pyc_path)

    if result.success:
        print(f"Reconstructed to: {result.output_path}")
    else:
        print(f"Error: {result.message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

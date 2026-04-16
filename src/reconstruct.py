import dis
import marshal
import sys
import types
from dataclasses import dataclass
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
        return 16
    elif magic in (
        b"\xee\x0d\x0d\x0a",
        b"\xef\x0d\x0d\x0a",
        b"\xf0\x0d\x0d\x0a",
        b"\xf1\x0d\x0d\x0a",
    ):
        return 12
    elif magic in (b"\xeb\x0d\x0d\x0a", b"\xec\x0d\x0d\x0a", b"\xed\x0d\x0d\x0a"):
        return 8
    return 16 if file_size > 16 else 8


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
            name = const.co_name
            if name not in ("<module>", "<lambda>", "__init__"):
                output.append("")
                output.append(_reconstruct_code(const, indent))

    return "\n".join(output)


def _get_name(code: types.CodeType, arg: int | None, is_local: bool = True) -> str:
    if arg is None:
        return "?"
    if is_local:
        if arg < len(code.co_varnames):
            return code.co_varnames[arg]
        return f"local_{arg}"
    else:
        if arg < len(code.co_names):
            return code.co_names[arg]
        return f"name_{arg}"


def _format_const(arg_repr: str) -> str:
    if arg_repr in ("None", "Ellipsis"):
        return arg_repr
    if arg_repr == "True":
        return "True"
    if arg_repr == "False":
        return "False"
    return arg_repr


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
        "CALL_INTRINSIC_1",
        "CALL_INTRINSIC_2",
        "LOAD_BUILD_CLASS",
        "LIST_EXTEND",
        "SET_UPDATE",
        "MAP_ADD",
    }

    def popn(n: int):
        result = []
        for _ in range(min(n, len(stack))):
            result.insert(0, stack.pop())
        return result

    while i < len(instructions):
        instr = instructions[i]
        op = instr.opname
        arg = instr.arg
        arg_repr = instr.argrepr

        if op in skip_ops:
            i += 1
            continue

        if op == "LOAD_CONST":
            if arg_repr and arg_repr not in ("None", "Ellipsis", "True", "False"):
                stack.append(_format_const(arg_repr))
            elif arg is not None and arg < len(code.co_consts):
                c = code.co_consts[arg]
                if isinstance(c, str):
                    stack.append(f"'{c}'")
                elif isinstance(c, (int, float)):
                    stack.append(str(c))
                elif isinstance(c, bytes):
                    stack.append(f"b'{c[:20].decode('utf-8', errors='replace')}...'")
                else:
                    stack.append(repr(c))
            else:
                stack.append("None")

        elif op == "LOAD_FAST":
            stack.append(_get_name(code, arg, True))

        elif op == "LOAD_NAME":
            stack.append(_get_name(code, arg, False))

        elif op == "LOAD_GLOBAL":
            if arg is not None and (arg & 0x08):
                idx = arg & 0x0F
                if idx < len(code.co_names):
                    stack.append(f"__builtins__.{code.co_names[idx]}")
                else:
                    stack.append("__builtins__")
            else:
                stack.append(_get_name(code, arg, False))

        elif op == "STORE_FAST":
            if stack and arg is not None:
                val = stack.pop()
                name = _get_name(code, arg, True)
                lines.append(f"{name} = {val}")

        elif op == "STORE_NAME":
            if stack and arg is not None:
                val = stack.pop()
                name = _get_name(code, arg, False)
                lines.append(f"{name} = {val}")

        elif op == "STORE_GLOBAL":
            if stack and arg is not None:
                val = stack.pop()
                name = _get_name(code, arg, False)
                lines.append(f"global {name}")
                lines.append(f"{name} = {val}")

        elif op == "DELETE_FAST":
            if arg is not None:
                name = _get_name(code, arg, True)
                lines.append(f"del {name}")

        elif op == "DELETE_NAME":
            if arg is not None:
                name = _get_name(code, arg, False)
                lines.append(f"del {name}")

        elif op == "CALL":
            func = stack.pop() if stack else "?"
            args = popn(arg) if arg else []
            args_str = ", ".join(args) if args else ""
            lines.append(f"{func}({args_str})")
            stack.clear()

        elif op == "RETURN_VALUE":
            if stack:
                val = stack.pop()
                lines.append(f"return {val}")
            else:
                lines.append("return")

        elif op == "RAISE_VARARGS":
            if arg and arg > 0 and stack:
                exc = stack.pop()
                if arg == 1:
                    lines.append(f"raise {exc}")
                elif arg == 2:
                    from_val = stack.pop() if stack else "None"
                    lines.append(f"raise {exc} from {from_val}")
            else:
                lines.append("raise")

        elif op == "PRINT":
            if stack:
                val = stack.pop()
                lines.append(f"print({val})")

        elif op == "POP_JUMP_IF_FALSE":
            if stack:
                cond = stack.pop()
                target = arg if arg else 0
                lines.append(f"if not {cond}:")
                lines.append("    pass")

        elif op == "POP_JUMP_IF_TRUE":
            if stack:
                cond = stack.pop()
                lines.append(f"if {cond}:")
                lines.append("    pass")

        elif op == "FOR_ITER":
            if stack:
                target = stack.pop() if stack else "iter"
                lines.append(f"for _ in {target}:")
                lines.append("    pass")

        elif op == "GET_ITER":
            pass

        elif op == "JUMP_FORWARD":
            pass

        elif op == "JUMP_ABSOLUTE":
            pass

        elif op == "BUILD_LIST":
            count = arg if arg else 0
            items = popn(count)
            if items:
                lines.append(f"[{', '.join(items)}]")
                stack.append(f"[{', '.join(items)}]")
            else:
                lines.append("[]")
                stack.append("[]")

        elif op == "BUILD_TUPLE":
            count = arg if arg else 0
            items = popn(count)
            if items:
                lines.append(f"({', '.join(items)},)")
                stack.append(f"({', '.join(items)},)")

        elif op == "BUILD_SET":
            count = arg if arg else 0
            items = popn(count)
            if items:
                lines.append(f"{{{', '.join(items)}}}")
                stack.append(f"{{{', '.join(items)}}}")

        elif op == "BUILD_DICT":
            count = arg if arg else 0
            items = popn(count * 2)
            pairs = []
            for j in range(0, len(items), 2):
                if j + 1 < len(items):
                    pairs.append(f"{items[j]}: {items[j + 1]}")
                else:
                    pairs.append(str(items[j]))
            if pairs:
                lines.append(f"{{{', '.join(pairs)}}}")
                stack.append(f"{{{', '.join(pairs)}}}")
            else:
                lines.append("{}")
                stack.append("{}")

        elif op == "BINARY_OP":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                op_map = {
                    "+": "+",
                    "-": "-",
                    "*": "*",
                    "/": "//",
                    "%": "%",
                    "**": "**",
                    "//": "//",
                    "<<": "<<",
                    ">>": ">>",
                    "&": "&",
                    "|": "|",
                    "^": "^",
                }
                op_str = op_map.get(str(arg_repr), str(arg_repr) if arg_repr else "+")
                stack.append(f"({a} {op_str} {b})")

        elif op == "BINARY_ADD":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                stack.append(f"({a} + {b})")

        elif op == "BINARY_MULTIPLY":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                stack.append(f"({a} * {b})")

        elif op == "COMPARE_OP":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                cmp_map = {
                    "<": "<",
                    "<=": "<=",
                    "==": "==",
                    "!=": "!=",
                    ">": ">",
                    ">=": ">=",
                    "in": "in",
                    "not in": "not in",
                    "is": "is",
                    "is not": "is not",
                }
                cmp_str = cmp_map.get(str(arg_repr), str(arg_repr) if arg_repr else "==")
                stack.append(f"({a} {cmp_str} {b})")

        elif op == "UNARY_NEGATIVE":
            if stack:
                val = stack.pop()
                stack.append(f"(-{val})")

        elif op == "UNARY_POSITIVE":
            if stack:
                val = stack.pop()
                stack.append(f"(+{val})")

        elif op == "UNARY_NOT":
            if stack:
                val = stack.pop()
                stack.append(f"(not {val})")

        elif op == "MAKE_FUNCTION":
            lines.append("# function defined")

        elif op == "IMPORT_NAME":
            if arg is not None and arg < len(code.co_names):
                name = code.co_names[arg]
                lines.append(f"import {name}")

        elif op == "IMPORT_FROM":
            if arg is not None and arg < len(code.co_names):
                name = code.co_names[arg]
                lines.append(f"from ... import {name}")

        elif op == "LOAD_ATTR":
            if stack and arg is not None:
                attr = _get_name(code, arg, False)
                obj = stack.pop() if stack else "self"
                stack.append(f"{obj}.{attr}")

        elif op == "STORE_ATTR":
            if len(stack) >= 2 and arg is not None:
                val = stack.pop()
                attr = _get_name(code, arg, False)
                obj = stack.pop() if stack else "self"
                lines.append(f"{obj}.{attr} = {val}")

        elif op == "DELETE_ATTR":
            if stack and arg is not None:
                attr = _get_name(code, arg, False)
                obj = stack.pop() if stack else "self"
                lines.append(f"del {obj}.{attr}")

        elif op == "BUILD_SLICE":
            if arg == 2 and len(stack) >= 2:
                stop = stack.pop()
                start = stack.pop()
                stack.append(f"slice({start}, {stop})")
            elif arg == 3 and len(stack) >= 3:
                step = stack.pop()
                stop = stack.pop()
                start = stack.pop()
                stack.append(f"slice({start}, {stop}, {step})")

        elif op == "SUBSCR":
            if len(stack) >= 2:
                idx = stack.pop()
                obj = stack.pop() if stack else "?"
                stack.append(f"{obj}[{idx}]")

        elif op == "STORE_SUBSCR":
            if len(stack) >= 3:
                val = stack.pop()
                idx = stack.pop()
                obj = stack.pop() if stack else "?"
                lines.append(f"{obj}[{idx}] = {val}")

        elif op == "DELETE_SUBSCR":
            if len(stack) >= 2:
                idx = stack.pop()
                obj = stack.pop() if stack else "?"
                lines.append(f"del {obj}[{idx}]")

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

        elif op in ("POP_TOP", "ROT_TWO", "ROT_THREE", "ROT_FOUR"):
            if stack:
                stack.pop()

        elif op == "DUP_TOP":
            if stack:
                stack.append(stack[-1])

        i += 1

    return lines


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

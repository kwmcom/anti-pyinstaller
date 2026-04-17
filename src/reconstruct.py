import dis
import marshal
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum, auto


class IRType(Enum):
    MODULE = auto()
    CLASS = auto()
    FUNCTION = auto()


@dataclass
class IRNode:
    name: str
    ir_type: IRType
    code: types.CodeType | None = None
    args: list[str] = field(default_factory=list)
    defaults: list = field(default_factory=list)
    body: list[str] = field(default_factory=list)
    children: list["IRNode"] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


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

        ir = _build_ir(code_obj)
        output = _emit_ir(ir)

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


def _build_ir(code: types.CodeType) -> IRNode:
    instructions = list(dis.get_instructions(code))

    module = IRNode(name="<module>", ir_type=IRType.MODULE, code=code)
    module.imports = _extract_imports(code)

    module_defs = _extract_module_definitions(code, instructions)

    for def_type, def_name, def_code in module_defs:
        if def_type == "class":
            class_node = _build_class_ir(def_code, def_name)
            module.children.append(class_node)
        else:
            func_node = _build_function_ir(def_code)
            module.children.append(func_node)

    return module


def _extract_module_definitions(code: types.CodeType, instructions: list):
    definitions = []
    pending_class = None
    pending_func = None

    skip_names = {
        "__init__",
        "__annotate__",
        "__static_attributes__",
        "__annotate_func__",
        "__classdictcell__",
    }

    i = 0
    while i < len(instructions):
        instr = instructions[i]
        op = instr.opname

        if op == "LOAD_BUILD_CLASS":
            pending_class = True

        elif op == "MAKE_FUNCTION":
            pending_func = True

        elif op == "STORE_NAME":
            arg = instr.arg
            if arg is not None and arg < len(code.co_names):
                name = code.co_names[arg]
                if name in skip_names:
                    i += 1
                    continue

                if pending_class:
                    for const in code.co_consts:
                        if isinstance(const, types.CodeType):
                            class_name = _get_class_name(const, code)
                            if class_name == name and _is_class_definition(const):
                                definitions.append(("class", name, const))
                                pending_class = None
                                break

                elif pending_func:
                    for const in code.co_consts:
                        if isinstance(const, types.CodeType):
                            if const.co_name == name and not _is_class_definition(const):
                                definitions.append(("function", name, const))
                                pending_func = None
                                break

        i += 1

    return definitions


def _extract_imports(code: types.CodeType) -> list[str]:
    imports = []
    current_module = None
    from_names = []
    seen = set()

    for instr in dis.get_instructions(code):
        if instr.opname == "IMPORT_NAME":
            if instr.arg is not None and instr.arg < len(code.co_names):
                current_module = code.co_names[instr.arg]

                next_instr = None
                try:
                    idx = list(dis.get_instructions(code)).index(instr)
                    all_instrs = list(dis.get_instructions(code))
                    if idx + 1 < len(all_instrs):
                        next_instr = all_instrs[idx + 1].opname
                except:
                    pass

                if next_instr != "IMPORT_FROM":
                    if current_module not in seen and not current_module.startswith("_"):
                        imports.append(f"import {current_module}")
                        seen.add(current_module)

                from_names = []

        elif instr.opname == "IMPORT_FROM":
            if instr.arg is not None and instr.arg < len(code.co_names):
                name = code.co_names[instr.arg]
                from_names.append(name)

        elif instr.opname == "STORE_NAME":
            if current_module and from_names:
                if current_module not in seen and not current_module.startswith("_"):
                    import_str = f"from {current_module} import {', '.join(from_names)}"
                    imports.append(import_str)
                    seen.add(current_module)

            current_module = None
            from_names = []

    return imports


def _extract_nested_definitions(code: types.CodeType):
    functions = []
    classes = []

    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name not in ("<module>", "<lambda>", "__init__"):
                if const.co_name not in (
                    "__annotate__",
                    "__static_attributes__",
                    "__annotate_func__",
                ):
                    if _is_class_definition(const):
                        class_name = _get_class_name(const, code)
                        if class_name:
                            classes.append((const, class_name))
                    else:
                        functions.append(const)

    return functions, classes


def _is_class_definition(nested_code: types.CodeType) -> bool:
    instructions = list(dis.get_instructions(nested_code))
    if instructions and instructions[0].opname == "MAKE_CELL":
        return True
    return False


def _get_class_name(class_code: types.CodeType, parent_code: types.CodeType) -> str | None:
    for i, const in enumerate(parent_code.co_consts):
        if const is class_code:
            if i + 1 < len(parent_code.co_consts):
                next_const = parent_code.co_consts[i + 1]
                if isinstance(next_const, str):
                    return next_const
    return class_code.co_name


def _build_function_ir(code: types.CodeType) -> IRNode:
    args = list(code.co_varnames[: code.co_argcount])
    kwonly = code.co_kwonlyargcount
    if kwonly:
        args.append("*")
        args.extend(code.co_varnames[code.co_argcount : code.co_argcount + kwonly])

    func_node = IRNode(
        name=code.co_name,
        ir_type=IRType.FUNCTION,
        code=code,
        args=args,
    )

    func_defs, class_defs = _extract_nested_definitions(code)
    for func_code in func_defs:
        func_node.children.append(_build_function_ir(func_code))

    for class_code, class_name in class_defs:
        func_node.children.append(_build_class_ir(class_code, class_name))

    func_node.body = _extract_body_instructions(code, list(dis.get_instructions(code)))

    return func_node


def _build_class_ir(code: types.CodeType, name: str) -> IRNode:
    class_node = IRNode(
        name=name,
        ir_type=IRType.CLASS,
        code=code,
    )

    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name not in (
                "<module>",
                "<lambda>",
                "__init__",
                "__annotate__",
                "__static_attributes__",
                "__annotate_func__",
            ):
                func_node = _build_function_ir(const)
                class_node.children.append(func_node)

    class_node.body = []

    return class_node


def _extract_body_instructions(code: types.CodeType, instructions: list) -> list[str]:
    lines = []
    stack = []

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
        "SETUP_FINALLY",
        "WITH_EXCEPT_START",
        "END_FINALLY",
    }

    internal_attrs = {
        "__module__",
        "__qualname__",
        "__doc__",
        "__class__",
        "__dict__",
        "__weakref__",
    }

    def popn(n: int):
        result = []
        for _ in range(min(n, len(stack))):
            result.insert(0, stack.pop())
        return result

    i = 0
    while i < len(instructions):
        instr = instructions[i]
        op = instr.opname
        arg = instr.arg

        if op in skip_ops:
            i += 1
            continue

        if op == "LOAD_CONST":
            stack.append(_format_const(arg, code))

        elif op == "LOAD_FAST":
            stack.append(_get_local_name(arg, code))

        elif op == "LOAD_NAME":
            stack.append(_get_name(arg, code))

        elif op == "LOAD_GLOBAL":
            stack.append(_get_global_name(arg, code, instr))

        elif op == "STORE_FAST":
            if stack and arg is not None:
                val = stack.pop()
                name = _get_local_name(arg, code)
                if name not in internal_attrs:
                    lines.append(f"{name} = {val}")

        elif op == "STORE_NAME":
            if stack and arg is not None:
                val = stack.pop()
                name = _get_name(arg, code)
                if name not in internal_attrs:
                    lines.append(f"{name} = {val}")

        elif op == "CALL":
            if stack:
                func = stack.pop()
                args = popn(arg) if arg else []
                args_str = ", ".join(args) if args else ""

                if not func.startswith("'"):
                    result = f"{func}({args_str})" if args_str else f"{func}()"
                    lines.append(result)
                stack.clear()

        elif op == "RETURN_VALUE":
            if stack:
                val = stack.pop()
                if val != "None":
                    lines.append(f"return {val}")
            else:
                lines.append("return")
            break

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

        elif op == "POP_JUMP_IF_FALSE":
            if stack:
                cond = stack.pop()
                lines.append(f"if {cond}:")
                lines.append("    pass")

        elif op == "POP_JUMP_IF_TRUE":
            if stack:
                cond = stack.pop()
                lines.append(f"if {cond}:")
                lines.append("    pass")

        elif op == "FOR_ITER":
            if stack:
                target = stack.pop() if stack else "_"
                lines.append(f"for {target} in ...:")
                lines.append("    pass")

        elif op == "BUILD_LIST":
            count = arg if arg else 0
            items = popn(count)
            if items:
                stack.append(f"[{', '.join(items)}]")
            else:
                stack.append("[]")

        elif op == "BUILD_TUPLE":
            count = arg if arg else 0
            items = popn(count)
            if items:
                s = ", ".join(items)
                stack.append(f"({s},)" if len(items) == 1 else f"({s})")
            else:
                stack.append("()")

        elif op == "BUILD_DICT":
            count = arg if arg else 0
            items = popn(count * 2)
            pairs = []
            for j in range(0, len(items), 2):
                if j + 1 < len(items):
                    pairs.append(f"{items[j]}: {items[j + 1]}")
            if pairs:
                stack.append(f"{{{', '.join(pairs)}}}")
            else:
                stack.append("{}")

        elif op == "BINARY_OP":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                stack.append(f"({a} + {b})")

        elif op == "BINARY_ADD":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                stack.append(f"({a} + {b})")

        elif op == "COMPARE_OP":
            if len(stack) >= 2:
                b = stack.pop()
                a = stack.pop()
                stack.append(f"({a} == {b})")

        elif op == "LOAD_ATTR":
            if stack and arg is not None:
                attr = _get_attr_name(arg, code, instr)
                obj = stack.pop() if stack else "self"
                stack.append(f"{obj}.{attr}")

        elif op == "STORE_ATTR":
            if len(stack) >= 2 and arg is not None:
                val = stack.pop()
                attr = _get_attr_name(arg, code, instr)
                obj = stack.pop() if stack else "self"
                lines.append(f"{obj}.{attr} = {val}")

        elif op == "SUBSCR":
            if len(stack) >= 2:
                idx = stack.pop()
                obj = stack.pop() if stack else "_"
                stack.append(f"{obj}[{idx}]")

        elif op in ("POP_TOP", "ROT_TWO", "ROT_THREE", "ROT_FOUR"):
            if stack:
                stack.pop()

        i += 1

    return lines


def _format_const(arg: int | None, code: types.CodeType) -> str:
    if arg is None or arg >= len(code.co_consts):
        return "None"
    c = code.co_consts[arg]
    if c is None:
        return "None"
    if c is Ellipsis:
        return "..."
    if isinstance(c, bool):
        return "True" if c else "False"
    if isinstance(c, str):
        if len(c) > 50:
            return f"'{c[:50]}...'"
        return f"'{c}'"
    if isinstance(c, bytes):
        return f"b'{c[:20].decode('utf-8', errors='replace')}...'"
    if isinstance(c, (int, float)):
        return str(c)
    if isinstance(c, tuple):
        items = [str(x) for x in c]
        return f"({', '.join(items)},)" if len(c) == 1 else f"({', '.join(items)})"
    if isinstance(c, (list, dict, set)):
        return "[]" if isinstance(c, list) else "{}"
    return repr(c)


def _get_local_name(arg: int | None, code: types.CodeType) -> str:
    if arg is None:
        return "_"
    if arg < len(code.co_varnames):
        return code.co_varnames[arg]
    return f"var_{arg}"


def _get_name(arg: int | None, code: types.CodeType) -> str:
    if arg is None:
        return "_"
    if arg < len(code.co_names):
        return code.co_names[arg]
    return f"name_{arg}"


def _get_global_name(arg: int | None, code: types.CodeType, instr) -> str:
    if arg is None:
        return "_"
    idx = arg >> 1
    argrepr = instr.argrepr
    if idx < len(code.co_names):
        if "+ NULL" in argrepr:
            return argrepr.split(" + NULL")[0]
        return code.co_names[idx]
    return f"_global_{idx}"


def _get_attr_name(arg: int | None, code: types.CodeType, instr) -> str:
    if arg is None:
        return "attr"
    argrepr = instr.argrepr
    if "+ NULL|" in argrepr:
        return argrepr.split(" + NULL|")[0]
    if " + NULL" in argrepr:
        return argrepr.split(" + NULL")[0]
    if arg < len(code.co_names):
        return code.co_names[arg]
    return f"attr_{arg}"


def _emit_ir(node: IRNode, indent: int = 0) -> str:
    prefix = "    " * indent
    lines = []

    if node.ir_type == IRType.MODULE:
        for imp in node.imports:
            lines.append(imp)

        for child in node.children:
            lines.append(_emit_ir(child, indent))

    elif node.ir_type == IRType.CLASS:
        lines.append(f"class {node.name}:")
        for child in node.children:
            lines.append(_emit_ir(child, indent + 1))
        for stmt in node.body:
            if stmt.strip():
                lines.append(f"    {prefix}{stmt}")

    elif node.ir_type == IRType.FUNCTION:
        args_str = ", ".join(node.args) if node.args else ""
        lines.append(f"def {node.name}({args_str}):")
        for child in node.children:
            lines.append(_emit_ir(child, indent + 1))
        for stmt in node.body:
            if stmt.strip():
                lines.append(f"    {prefix}{stmt}")

    return "\n".join(lines)


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

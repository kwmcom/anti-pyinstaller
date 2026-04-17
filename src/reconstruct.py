"""
Bytecode reconstructor for Python 3.11+ - converts .pyc to pseudo-Python source.

This is a work in progress. The reconstruction handles:
- Imports (import, from...import)
- Class and function definitions with decorators
- Basic expressions (literals, variables, attribute access)
- Simple function calls
- Basic control flow (if, for, while - simplified)
- Return statements

Limitations:
- Complex control flow (nested conditionals, try/except/with) is incomplete
- Keyword arguments may not reconstruct properly
- Binary operations have limited operator support
- Some Python 3.11+ specific opcodes not fully handled
"""

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
    decorators: list[str] = field(default_factory=list)


@dataclass
class ReconstructResult:
    success: bool
    output_path: Path | None
    message: str


@dataclass
class BasicBlock:
    """A control flow block - straight-line instructions with single entry."""
    start_offset: int
    instructions: list = field(default_factory=list)
    successors: list["BasicBlock"] = field(default_factory=list)
    predecessors: list["BasicBlock"] = field(default_factory=list)
    except_edges: list["BasicBlock"] = field(default_factory=list)  # For TRY blocks

    def __hash__(self) -> int:
        return hash(self.start_offset)

    def __eq__(self, other) -> bool:
        if not isinstance(other, BasicBlock):
            return False
        return self.start_offset == other.start_offset

    @property
    def end_offset(self) -> int:
        if self.instructions:
            return self.instructions[-1].offset
        return self.start_offset

    @property
    def is_terminator(self) -> bool:
        if not self.instructions:
            return False
        last_op = self.instructions[-1].opname
        return last_op in ("RETURN_VALUE", "RAISE_VARARGS")


class CFGValidator:
    """Validates CFG for structural correctness before interpretation."""

    @staticmethod
    def validate(blocks: list[BasicBlock]) -> tuple[bool, list[str], float]:
        """Validate CFG, return (is_valid, warnings, confidence_score)."""
        warnings = []
        confidence = 1.0

        # Check 1: All blocks have valid terminators
        for block in blocks:
            if not block.instructions:
                warnings.append(f"Block@{block.start_offset}: empty block")
                confidence -= 0.05
                continue

            last_op = block.instructions[-1].opname
            # Each block must end with terminator or have successors
            if last_op not in ("RETURN_VALUE", "RAISE_VARARGS",
                              "JUMP_ABSOLUTE", "JUMP_FORWARD",
                              "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                              "FOR_ITER"):
                if not block.successors:
                    # Implicit fallthrough - OK if next block exists
                    pass

        # Check 2: Edge consistency
        for block in blocks:
            for succ in block.successors:
                if block not in succ.predecessors:
                    warnings.append(f"Block@{block.start_offset}: inconsistent edge to Block@{succ.start_offset}")
                    confidence -= 0.1

        # Check 3: Reachability
        # All blocks should be reachable from entry (offset 0)
        entry = None
        for b in blocks:
            if b.start_offset == 0:
                entry = b
                break

        if entry:
            reachable = CFGValidator._find_reachable(entry)
            unreachable = set(blocks) - reachable
            if unreachable:
                warnings.append(f"{len(unreachable)} unreachable blocks detected")
                confidence -= 0.1 * len(unreachable)

        # Check 4: No overlapping blocks
        covered_offsets = set()
        for block in blocks:
            for instr in block.instructions:
                if instr.offset in covered_offsets:
                    warnings.append(f"Duplicate coverage at offset {instr.offset}")
                    confidence -= 0.2
                covered_offsets.add(instr.offset)

        is_valid = confidence > 0.5
        return is_valid, warnings, max(0.0, confidence)

    @staticmethod
    def _find_reachable(start: BasicBlock) -> set[BasicBlock]:
        """Find all reachable blocks from start via DFS."""
        reachable = set()
        stack = [start]
        while stack:
            block = stack.pop()
            if block in reachable:
                continue
            reachable.add(block)
            for succ in block.successors:
                stack.append(succ)
        return reachable


class CFGBuilder:
    """Builds control flow graph from bytecode."""

    def __init__(self, code: types.CodeType):
        self.code = code
        self.instructions = list(dis.get_instructions(code))
        self.blocks: dict[int, BasicBlock] = {}  # start_offset -> block
        self.offset_to_idx: dict[int, int] = {}  # offset -> instruction index

        for i, instr in enumerate(self.instructions):
            self.offset_to_idx[instr.offset] = i

    def build(self) -> tuple[list[BasicBlock], list[str], float]:
        """Build CFG and return (blocks, warnings, confidence)."""
        # Step 1: Find all block leaders (entry points)
        leaders = self._find_block_leaders()

        # Step 2: Create blocks and assign instructions
        self._create_blocks(leaders)

        # Step 3: Connect edges (successors)
        self._connect_edges()

        blocks = list(self.blocks.values())

        # Step 4: Validate
        is_valid, warnings, confidence = CFGValidator.validate(blocks)

        if not is_valid:
            warnings.insert(0, f"CFG validation failed (confidence={confidence:.2f})")

        return blocks, warnings, confidence

    def _find_block_leaders(self) -> set[int]:
        """Find all instruction offsets that start a new block."""
        leaders = {0}  # First instruction is always a leader

        for i, instr in enumerate(self.instructions):
            op = instr.opname

            # A: Jump targets start new blocks
            if hasattr(instr, 'jump_target') and instr.jump_target is not None:
                leaders.add(instr.jump_target)

            # For opcodes with jump targets, also mark fallthrough
            if op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                      "JUMP_IF_TRUE", "JUMP_IF_FALSE",
                      "FOR_ITER"):
                # Fallthrough to next instruction
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].offset)

            # B: Instructions after terminators start new blocks
            if op in ("RETURN_VALUE", "RAISE_VARARGS"):
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].offset)

            # C: JUMP_ABSOLUTE/JUMP_FORWARD target next instr
            if op in ("JUMP_ABSOLUTE", "JUMP_FORWARD"):
                if hasattr(instr, 'jump_target') and instr.jump_target is not None:
                    leaders.add(instr.jump_target)
                # Instruction after unconditional jump is a leader (if any)
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].offset)

        return leaders

    def _create_blocks(self, leaders: set[int]):
        """Create blocks and assign instructions to them."""
        current_block = None

        for instr in self.instructions:
            # Start new block if this instruction is a leader
            if instr.offset in leaders and (current_block is None or instr.offset != current_block.start_offset):
                current_block = BasicBlock(start_offset=instr.offset)
                self.blocks[instr.offset] = current_block

            # Add instruction to current block
            if current_block is not None:
                current_block.instructions.append(instr)

    def _connect_edges(self):
        """Connect block successors based on control flow."""
        block_starts = sorted(self.blocks.keys())

        for block in self.blocks.values():
            if not block.instructions:
                continue

            last_instr = block.instructions[-1]
            op = last_instr.opname

            # Unconditional jump: 1 successor
            if op in ("JUMP_ABSOLUTE", "JUMP_FORWARD"):
                if hasattr(last_instr, 'jump_target') and last_instr.jump_target is not None:
                    target_block = self.blocks.get(last_instr.jump_target)
                    if target_block:
                        block.successors.append(target_block)
                        target_block.predecessors.append(block)

            # Conditional jump: 2 successors (true branch, false/fallthrough)
            elif op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                       "JUMP_IF_TRUE", "JUMP_IF_FALSE"):
                # Jump target (taken branch)
                if hasattr(last_instr, 'jump_target') and last_instr.jump_target is not None:
                    target_block = self.blocks.get(last_instr.jump_target)
                    if target_block and target_block not in block.successors:
                        block.successors.append(target_block)
                        target_block.predecessors.append(block)

                # Fallthrough (not taken)
                next_block = self._get_next_block(block.end_offset)
                if next_block and next_block not in block.successors:
                    block.successors.append(next_block)
                    next_block.predecessors.append(block)

            # FOR_ITER: 2 successors (loop body, exit)
            elif op == "FOR_ITER":
                # Jump target is loop exit
                if hasattr(last_instr, 'jump_target') and last_instr.jump_target is not None:
                    exit_block = self.blocks.get(last_instr.jump_target)
                    if exit_block and exit_block not in block.successors:
                        block.successors.append(exit_block)
                        exit_block.predecessors.append(block)

                # Fallthrough is loop body
                next_block = self._get_next_block(block.end_offset)
                if next_block and next_block not in block.successors:
                    block.successors.append(next_block)
                    next_block.predecessors.append(block)

            # Return/Raise: 0 successors (terminator)
            elif op in ("RETURN_VALUE", "RAISE_VARARGS"):
                pass  # No successors

            # Default: fallthrough to next block
            else:
                next_block = self._get_next_block(block.end_offset)
                if next_block and next_block not in block.successors:
                    block.successors.append(next_block)
                    next_block.predecessors.append(block)

    def _get_next_block(self, after_offset: int) -> BasicBlock | None:
        """Get the block starting after given offset."""
        for start, block in self.blocks.items():
            if start > after_offset:
                return block
        return None


def reconstruct(pyc_path: Path, output_path: Path | None = None) -> ReconstructResult:
    if not pyc_path.exists():
        return ReconstructResult(False, None, "File not found")

    try:
        with open(pyc_path, "rb") as f:
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


def _build_ir(code: types.CodeType, name: str = "<module>") -> IRNode:
    """Build IR tree from code object using scope-aware traversal.

    Uses code object hierarchy (co_consts) not opcode guessing.
    """
    module = IRNode(name=name, ir_type=IRType.MODULE, code=code)
    module.imports = _extract_imports(code)

    # Build scope tree from code object hierarchy
    scope_tree = _build_scope_tree(code)

    # Convert scope tree to IR nodes
    for item in scope_tree:
        node = _scope_to_ir(item)
        if node:
            module.children.append(node)

    return module


def _is_class_code(code: types.CodeType) -> bool:
    """Check if a code object represents a class definition."""
    # Class code objects have internal markers
    instructions = list(dis.get_instructions(code))

    # Must have MAKE_CELL early (class cell)
    has_cell = False
    for instr in instructions:
        if instr.opname == "MAKE_CELL":
            has_cell = True
            break
        # Stop scanning after a few instructions
        if instr.offset > 20:
            break

    # Class code co_name is the class name, code runs in class body context
    return has_cell and code.co_name not in ("<module>", "<lambda>")


def _build_scope_tree(code: types.CodeType) -> list[dict]:
    """Build scope tree by walking code object hierarchy.

    Returns list of scope items, each with type, name, code, and children.
    """
    scopes = []

    # Process code objects in order they appear in co_consts
    # Track which code objects are already assigned as children
    assigned = set()

    for const in code.co_consts:
        if not isinstance(const, types.CodeType):
            continue
        if const in assigned:
            continue
        if const.co_name in ("<module>", "<lambda>", "<genexpr>", "<listcomp>", "<dictcomp>", "<setcomp>"):
            continue
        if const.co_name.startswith("__annotate__"):
            continue

        scope_info = _analyze_scope_item(const, assigned)
        if scope_info:
            scopes.append(scope_info)

    return scopes


def _analyze_scope_item(code: types.CodeType, assigned: set) -> dict | None:
    """Analyze a single code object and build its scope info."""

    if code.co_name.startswith("__") and code.co_name not in ("__init__",):
        return None

    is_class = _is_class_code(code)

    scope = {
        "type": "class" if is_class else "function",
        "name": code.co_name,
        "code": code,
        "children": [],
    }

    # Find nested definitions in this scope's code objects
    for const in code.co_consts:
        if not isinstance(const, types.CodeType):
            continue
        if const in assigned:
            continue

        # Skip special/dunder methods
        if const.co_name.startswith("__") and const.co_name not in ("__init__",):
            assigned.add(const)
            continue

        nested = _analyze_scope_item(const, assigned)
        if nested:
            scope["children"].append(nested)
            assigned.add(const)

    return scope


def _scope_to_ir(scope: dict) -> IRNode | None:
    """Convert scope dict to IRNode."""
    scope_type = scope.get("type")
    name = scope.get("name")
    code = scope.get("code")
    children = scope.get("children", [])

    if not code:
        return None

    if scope_type == "class":
        node = _build_class_from_scope(scope)
    else:
        node = _build_function_from_scope(scope)

    return node


def _build_class_from_scope(scope: dict) -> IRNode:
    """Build class IR node from scope info."""
    code = scope["code"]
    name = scope["name"]
    children_scopes = scope.get("children", [])

    class_node = IRNode(
        name=name,
        ir_type=IRType.CLASS,
        code=code,
    )

    # Convert children scopes to IR
    for child_scope in children_scopes:
        child_node = _scope_to_ir(child_scope)
        if child_node:
            class_node.children.append(child_node)

    return class_node


def _build_function_from_scope(scope: dict) -> IRNode:
    """Build function IR node from scope info."""
    code = scope["code"]
    name = scope["name"]
    children_scopes = scope.get("children", [])

    # Build args list from varnames
    args = list(code.co_varnames[:code.co_argcount])
    kwonly = code.co_kwonlyargcount
    if kwonly > 0:
        args.append("*")
        args.extend(code.co_varnames[code.co_argcount:code.co_argcount + kwonly])

    func_node = IRNode(
        name=name,
        ir_type=IRType.FUNCTION,
        code=code,
        args=args,
    )

    # Convert children scopes (nested functions/classes)
    for child_scope in children_scopes:
        child_node = _scope_to_ir(child_scope)
        if child_node:
            func_node.children.append(child_node)

    # Build function body with validation
    body, warnings, confidence = _extract_function_body(code)
    func_node.body = body
    # Could store warnings/confidence in node if we extend IRNode

    return func_node


def _extract_module_definitions(code: types.CodeType, instructions: list):
    """Extract top-level class and function definitions from module bytecode."""
    definitions = []
    skip_names = {
        "__init__", "__annotate__", "__static_attributes__",
        "__annotate_func__", "__classdictcell__", "__module__",
        "__qualname__", "__doc__", "__class__",
    }

    # Pre-index code objects by name
    code_objects_by_name = {}
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            code_objects_by_name[const.co_name] = const

    i = 0
    while i < len(instructions):
        instr = instructions[i]
        op = instr.opname

        if op in ("STORE_NAME", "STORE_GLOBAL"):
            arg = instr.arg
            if arg is not None and arg < len(code.co_names):
                name = code.co_names[arg]
                if name in skip_names:
                    i += 1
                    continue

                # Look backwards to determine if this is a class or function
                found_class = False
                found_func = False
                class_code = None
                func_code = None
                decorators = []

                for j in range(max(0, i - 25), i):
                    prev_op = instructions[j].opname

                    if prev_op == "LOAD_BUILD_CLASS":
                        # This is a class definition
                        if name in code_objects_by_name:
                            class_code = code_objects_by_name[name]
                            if _is_class_definition(class_code):
                                found_class = True

                    elif prev_op == "MAKE_FUNCTION":
                        # This is a function definition
                        if name in code_objects_by_name:
                            func_code = code_objects_by_name[name]
                            if not _is_class_definition(func_code) and func_code.co_name == name:
                                found_func = True

                    elif prev_op == "LOAD_NAME":
                        # Could be a decorator
                        dec_arg = instructions[j].arg
                        if dec_arg is not None and dec_arg < len(code.co_names):
                            dec_name = code.co_names[dec_arg]
                            if dec_name not in skip_names:
                                decorators.append(dec_name)

                if found_class and class_code:
                    definitions.append(("class", name, class_code, decorators))
                elif found_func and func_code:
                    definitions.append(("function", name, func_code, decorators))

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

            # Check next instruction
            next_is_import_from = False
            idx = list(dis.get_instructions(code)).index(instr)
            all_instrs = list(dis.get_instructions(code))
            if idx + 1 < len(all_instrs):
                next_is_import_from = all_instrs[idx + 1].opname == "IMPORT_FROM"

            if not next_is_import_from and current_module:
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


def _is_class_definition(nested_code: types.CodeType) -> bool:
    """Check if a code object represents a class definition."""
    instructions = list(dis.get_instructions(nested_code))
    for instr in instructions:
        if instr.opname in ("MAKE_CELL", "LOAD_BUILD_CLASS"):
            return True
    return False


def _build_function_ir(code: types.CodeType, decorators: list = None) -> IRNode:
    """Build IR for a function including nested definitions."""
    args = []
    argcount = code.co_argcount
    kwonly = code.co_kwonlyargcount

    if code.co_varnames:
        args = list(code.co_varnames[:argcount])
        if kwonly > 0:
            args.append("*")
            args.extend(code.co_varnames[argcount:argcount + kwonly])

    func_node = IRNode(
        name=code.co_name,
        ir_type=IRType.FUNCTION,
        code=code,
        args=args,
        decorators=decorators or [],
    )

    # Find nested functions/classes in this function
    nested_defs = _extract_nested_module_definitions(code)
    for def_info in nested_defs:
        if def_info["type"] == "class":
            func_node.children.append(_build_class_ir(def_info["code"], def_info["name"]))
        else:
            func_node.children.append(_build_function_ir(def_info["code"]))

    # Extract function body with validation
    body, warnings, confidence = _extract_function_body(code)
    func_node.body = body

    return func_node


def _extract_nested_module_definitions(code: types.CodeType):
    """Extract nested definitions from a code object."""
    definitions = []
    skip = {"<module>", "<lambda>", "__init__", "__annotate__", "__static_attributes__", "__annotate_func__"}

    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name not in skip:
                if _is_class_definition(const):
                    class_name = _get_class_name(const, code)
                    if class_name:
                        definitions.append({"type": "class", "name": class_name, "code": const})
                else:
                    definitions.append({"type": "function", "name": const.co_name, "code": const})

    return definitions


def _get_class_name(class_code: types.CodeType, parent_code: types.CodeType) -> str | None:
    """Get the actual class name from the parent code's consts."""
    for i, const in enumerate(parent_code.co_consts):
        if const is class_code:
            if i + 1 < len(parent_code.co_consts):
                next_const = parent_code.co_consts[i + 1]
                if isinstance(next_const, str):
                    return next_const
    return class_code.co_name


def _build_class_ir(code: types.CodeType, name: str, decorators: list = None) -> IRNode:
    """Build IR for a class."""
    class_node = IRNode(
        name=name,
        ir_type=IRType.CLASS,
        code=code,
        decorators=decorators or [],
    )

    # Extract methods from class code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            if const.co_name not in (
                "<module>", "<lambda>", "__annotate__", "__static_attributes__", "__annotate_func__"
            ):
                method_node = _build_function_ir(const)
                class_node.children.append(method_node)

    return class_node


def _extract_function_body(code: types.CodeType) -> tuple[list[str], list[str], float]:
    """Extract function body from CFG (structured, not linear).

    Returns: (statements, warnings, confidence_score)
    """
    # Build CFG first
    builder = CFGBuilder(code)
    blocks, warnings, confidence = builder.build()

    if not blocks:
        return ["pass"], ["CFG: no blocks generated"], 0.0

    if confidence < 0.5:
        # Low confidence - emit pseudo-IR, not Python
        return (
            [f"# CFG incomplete (confidence={confidence:.2f})", "pass"],
            warnings + ["Confidence below threshold, emitted placeholder"],
            confidence
        )

    # Build expression evaluator for each block
    evaluator = BlockEvaluator(code)

    # Find entry block (starts at offset 0)
    entry = None
    for block in blocks:
        if block.start_offset == 0 or (block.instructions and block.instructions[0].opname == "RESUME"):
            entry = block
            break
    if entry is None:
        entry = min(blocks, key=lambda b: b.start_offset)

    # Emit body from structured traversal
    stmts = _emit_cfg_body(entry, evaluator, set())

    # Combine evaluator confidence with CFG confidence
    total_confidence = confidence * evaluator.get_confidence()

    return stmts, warnings, total_confidence


def _emit_cfg_body(block: BasicBlock, evaluator: "BlockEvaluator", visited: set) -> list[str]:
    """Emit body from CFG traversal, handling branches."""
    if block.start_offset in visited:
        return ["# (merge block)"]
    visited.add(block.start_offset)

    result = []

    # Evaluate this block (expressions only, no control flow)
    block_statements = evaluator.evaluate_block(block)
    result.extend(block_statements)

    # Handle successors
    if len(block.successors) == 0:
        # No successors (return/raise) - done
        pass
    elif len(block.successors) == 1:
        # Fallthrough - continue to next block
        succ = block.successors[0]
        if not block.is_terminator:
            result.extend(_emit_cfg_body(succ, evaluator, visited))
    elif len(block.successors) == 2:
        # Conditional - emit if/else
        # Determine if this is if/else or if-only
        true_block, false_block = _classify_branches(block, block.successors[0], block.successors[1])

        # Get condition from last conditional instruction
        condition = evaluator.get_last_condition()

        if condition:
            result.append(f"if {condition}:")
            # True branch
            true_body = _emit_cfg_body(true_block, evaluator.copy(), visited.copy())
            for stmt in true_body:
                result.append(f"    {stmt}")

            # Check if false branch has content
            false_body = _emit_cfg_body(false_block, evaluator.copy(), visited.copy())
            if false_body and any(s.strip() and not s.startswith("#") for s in false_body):
                result.append("else:")
                for stmt in false_body:
                    result.append(f"    {stmt}")
    # else: more than 2 successors (switch) - not handling

    return result if result else ["pass"]


def _classify_branches(block: BasicBlock, succ1: BasicBlock, succ2: BasicBlock) -> tuple:
    """Classify which successor is true/false branch."""
    if not block.instructions:
        return succ1, succ2

    last_instr = block.instructions[-1]
    op = last_instr.opname

    # For POP_JUMP_IF_FALSE: target is jump_target (false branch), fallthrough is true
    # For POP_JUMP_IF_TRUE: target is jump_target (true branch), fallthrough is false
    if hasattr(last_instr, 'jump_target') and last_instr.jump_target is not None:
        jump_target = last_instr.jump_target
        # Find which successor matches jump target
        if succ1.start_offset == jump_target:
            jump_succ = succ1
            fall_succ = succ2
        else:
            jump_succ = succ2
            fall_succ = succ1

        if op in ("POP_JUMP_IF_FALSE",):
            # Jump if false, so fallthrough is true
            return fall_succ, jump_succ
        elif op in ("POP_JUMP_IF_TRUE",):
            # Jump if true
            return jump_succ, fall_succ

    return succ1, succ2


class BlockEvaluator:
    """Evaluates expressions within a single basic block (no control flow).

    Strict mode: no guessing, emit UNKNOWN_EXPRESSION on underflow.
    """

    UNKNOWN_EXPR = "UNKNOWN_EXPR"

    def __init__(self, code: types.CodeType):
        self.code = code
        self.stack: list[str] = []
        self.current_condition: str | None = None
        self.unknown_count = 0  # Track how many unknowns we emit

    def copy(self) -> "BlockEvaluator":
        new = BlockEvaluator(self.code)
        new.stack = self.stack.copy()
        return new

    def get_last_condition(self) -> str | None:
        return self.current_condition

    def evaluate_block(self, block: BasicBlock) -> list[str]:
        """Evaluate a block, return statements."""
        statements = []
        self.stack = []  # Fresh stack per block

        for instr in block.instructions:
            stmt = self._eval_instruction(instr)
            if stmt is not None:
                statements.append(stmt)

        return statements

    def _eval_instruction(self, instr) -> str | None:
        """Evaluate single instruction, return statement if any."""
        op = instr.opname
        arg = instr.arg

        # Skip structural opcodes
        if op in ("RESUME", "CACHE", "NOP", "NOT_TAKEN"):
            return None

        # Skip control flow (handled by CFG traversal)
        if op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                  "JUMP_ABSOLUTE", "JUMP_FORWARD", "FOR_ITER"):
            # Capture last conditional for if/else
            if op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE") and self.stack:
                self.current_condition = self.stack.pop()
            return None

        # Skip returns/raises (block terminators)
        if op in ("RETURN_VALUE", "RAISE_VARARGS"):
            if op == "RETURN_VALUE" and self.stack:
                val = self.stack.pop()
                if val != "None":
                    return f"return {val}"
                return "return"
            if op == "RAISE_VARARGS" and self.stack:
                exc = self.stack.pop()
                return f"raise {exc}"
            return None

        # Load operations (push onto stack)
        if op == "LOAD_CONST":
            self.stack.append(self._format_const(arg))
            return None

        if op in ("LOAD_FAST", "LOAD_FAST_BORROW", "LOAD_FAST_CHECK"):
            self.stack.append(self._get_varname(arg))
            return None

        if op in ("LOAD_NAME", "LOAD_GLOBAL"):
            self.stack.append(self._get_name(arg))
            return None

        if op == "LOAD_ATTR" and self.stack:
            obj = self.stack.pop()
            attr = self._get_name(arg)
            self.stack.append(f"{obj}.{attr}")
            return None

        # Store operations (pop from stack, emit statement)
        if op in ("STORE_FAST", "STORE_NAME", "STORE_GLOBAL"):
            if self.stack:
                val = self.stack.pop()
                name = self._get_varname(arg) if op == "STORE_FAST" else self._get_name(arg)
                if name and not name.startswith("__"):
                    return f"{name} = {val}"
            return None

        if op == "STORE_SUBSCR" and len(self.stack) >= 3:
            val = self.stack.pop()  # TOS
            idx = self.stack.pop()  # TOS1
            obj = self.stack.pop()  # TOS2
            return f"{obj}[{idx}] = {val}"

        # Call operations
        if op in ("CALL", "CALL_FUNCTION"):
            return self._emit_call(arg)

        # Binary operations
        if op == "BINARY_OP" and len(self.stack) >= 2:
            right = self.stack.pop()
            left = self.stack.pop()
            ops = {0: "+", 1: "-", 2: "*", 3: "/", 4: "//", 5: "%",
                   6: "@", 7: "**", 8: ">>", 9: "<<", 10: "&", 11: "^", 12: "|"}
            self.stack.append(f"({left} {ops.get(arg, '+')} {right})")
            return None

        if op == "COMPARE_OP" and len(self.stack) >= 2:
            right = self.stack.pop()
            left = self.stack.pop()
            cmps = {0: "<", 1: "<=", 2: "==", 3: "!=", 4: ">", 5: ">=",
                    8: "is", 9: "is not", 10: "in", 11: "not in"}
            self.stack.append(f"({left} {cmps.get(arg, '==')} {right})")
            return None

        if op == "CONTAINS_OP" and len(self.stack) >= 2:
            obj = self.stack.pop()
            container = self.stack.pop()
            if arg == 1:
                self.stack.append(f"{obj} not in {container}")
            else:
                self.stack.append(f"{obj} in {container}")
            return None

        if op == "BUILD_TUPLE":
            items = []
            for _ in range(min(arg, len(self.stack))):
                items.insert(0, self.stack.pop())
            if len(items) == 1:
                self.stack.append(f"({items[0]},)")
            else:
                self.stack.append(f"({', '.join(items)})")
            return None

        if op == "BUILD_LIST":
            items = []
            for _ in range(min(arg, len(self.stack))):
                items.insert(0, self.stack.pop())
            self.stack.append(f"[{', '.join(items)}]")
            return None

        if op == "BUILD_DICT":
            pairs = []
            for _ in range(min(arg, len(self.stack) // 2)):
                if len(self.stack) >= 2:
                    v = self.stack.pop()
                    k = self.stack.pop()
                    pairs.insert(0, f"{k}: {v}")
            self.stack.append(f"{{{', '.join(pairs)}}}")
            return None

        # Binary subscript (load)
        if op in ("BINARY_SUBSCR", "SUBSCR") and len(self.stack) >= 2:
            idx = self.stack.pop()
            obj = self.stack.pop()
            self.stack.append(f"{obj}[{idx}]")
            return None

        # POP_TOP - discard top of stack
        if op == "POP_TOP" and self.stack:
            self.stack.pop()
            return None

        # Unknown opcode - mark as unknown expression
        self.unknown_count += 1
        self.stack.append(f"OP_{op}_{arg}")
        return None

    def _emit_call(self, argc: int | None) -> str | None:
        """Emit function call - strict stack validation."""
        if argc is None:
            argc = 0

        # Require: argc args + 1 function
        required = argc + 1
        if len(self.stack) < required:
            # Stack underflow - punt
            self.stack.append(f"UNKNOWN_CALL(argc={argc})")
            return None

        args = []
        for _ in range(argc):
            args.insert(0, self.stack.pop())

        func = self.stack.pop()
        if " + NULL" in func:
            func = func.split(" + NULL")[0]
        if " + NULL|" in func:
            func = func.split(" + NULL|")[0]

        self.stack.append(f"{func}({', '.join(args)})")
        return None

    def _format_const(self, arg: int | None) -> str:
        if arg is None or arg >= len(self.code.co_consts):
            return "None"
        c = self.code.co_consts[arg]
        if c is None:
            return "None"
        if isinstance(c, bool):
            return "True" if c else "False"
        if isinstance(c, str):
            escaped = c.replace("'", "\\'").replace("\\", "\\\\")
            return f"'{escaped}'"
        if isinstance(c, (int, float)):
            return str(c)
        if isinstance(c, tuple):
            items = [repr(x) if isinstance(x, (int, str, float, bool)) else str(x) for x in c]
            return f"({', '.join(items)})" if len(c) != 1 else f"({items[0]},)"
        return repr(c)[:50]

    def _get_varname(self, arg: int | None) -> str:
        if arg is None:
            return "_"
        if arg < len(self.code.co_varnames):
            return self.code.co_varnames[arg]
        return f"var_{arg}"

    def _get_name(self, arg: int | None) -> str:
        if arg is None:
            return "_"
        idx = arg >> 1 if arg else arg
        if idx is not None and idx < len(self.code.co_names):
            return self.code.co_names[idx]
        if arg < len(self.code.co_names):
            return self.code.co_names[arg]
        return f"name_{arg}"

    def get_confidence(self) -> float:
        """Calculate confidence score based on unknowns."""
        # Simple heuristic: more unknowns = lower confidence
        if self.unknown_count == 0:
            return 1.0
        # Cap at some minimum
        return max(0.3, 1.0 - (self.unknown_count * 0.1))


class BytecodeEmitter:
    """Converts bytecode instructions to Python statements."""

    def __init__(self, code: types.CodeType):
        self.code = code
        self.stack: list[str] = []
        self.statements: list[str] = []

        # Binary operation mapping
        self.binops = {
            0: "+", 1: "-", 2: "*", 3: "/", 4: "//", 5: "%", 6: "@",
            7: "**", 8: ">>", 9: "<<", 10: "&", 11: "^", 12: "|",
        }

        # Comparison operators
        self.cmps = {
            0: "<", 1: "<=", 2: "==", 3: "!=", 4: ">", 5: ">=",
            8: "is", 9: "is not", 10: "in", 11: "not in"
        }

        # These opcodes should be skipped
        self.skip_ops = {
            "RESUME", "CACHE", "PUSH_NULL", "COPY_FREE_VARS",
            "LOAD_LOCALS", "MAKE_CELL", "SET_FUNCTION_ATTRIBUTE",
            "STORE_DEREF", "FREEZE_VALUE", "CALL_INTRINSIC_1",
            "CALL_INTRINSIC_2", "LOAD_BUILD_CLASS", "SETUP_FINALLY",
            "WITH_EXCEPT_START", "END_FINALLY", "NOP",
            "NOT_TAKEN", "LIST_EXTEND", "SET_UPDATE", "MAP_ADD",
        }

    def get_statements(self) -> list[str]:
        # Post-process to fix broken constructs from skipped exception opcodes
        fixed = []
        for stmt in self.statements:
            # Fix broken "if Exception:" statements from exception handling
            if stmt.strip().startswith("if "):
                # Check if condition looks like a type name (exception class)
                cond = stmt.split(":", 1)[0].replace("if ", "").strip()
                if cond and cond[0].isupper():
                    # This is likely "if FileNotFoundError:" or "if Exception:"
                    fixed.append(f"# TODO: exception handling for {cond}")
                    fixed.append("    pass")
                    continue
            fixed.append(stmt)
        return fixed

    def process(self, instr):
        op = instr.opname
        arg = instr.arg

        if op in self.skip_ops:
            return

        # Stack operations - loads
        if op == "LOAD_CONST":
            self.stack.append(self._format_const(arg))

        elif op in ("LOAD_FAST", "LOAD_FAST_BORROW", "LOAD_FAST_CHECK"):
            self.stack.append(self._get_varname(arg))

        elif op in ("LOAD_NAME", "LOAD_GLOBAL"):
            self.stack.append(self._get_name(arg))

        elif op == "LOAD_ATTR":
            if self.stack:
                obj = self.stack.pop()
                attr = self._get_name(arg)
                self.stack.append(f"{obj}.{attr}")

        elif op == "LOAD_METHOD":
            if self.stack:
                obj = self.stack.pop()
                method = self._get_name(arg)
                self.stack.append(f"{obj}.{method}")

        elif op == "LOAD_SMALL_INT" or op == "LOAD_SMALL_INTEGER":
            self.stack.append(str(arg if arg is not None else 0))

        elif op == "LOAD_COMMON_CONSTANT":
            consts = {0: "None", 1: "False", 2: "True", 3: "Ellipsis", 4: "NotImplemented"}
            self.stack.append(consts.get(arg, f"const_{arg}"))

        # Store operations
        elif op in ("STORE_FAST", "STORE_NAME", "STORE_GLOBAL"):
            if self.stack:
                val = self.stack.pop()
                name = self._get_varname(arg) if op == "STORE_FAST" else self._get_name(arg)
                if name and not name.startswith("__"):
                    self.statements.append(f"{name} = {val}")

        elif op == "STORE_ATTR":
            if len(self.stack) >= 1:
                val = self.stack.pop()
                obj = self.stack.pop() if self.stack else "self"
                attr = self._get_name(arg)
                self.statements.append(f"{obj}.{attr} = {val}")

        # Call operations
        elif op in ("CALL", "CALL_FUNCTION"):
            self._emit_call(arg)

        elif op == "CALL_KW":
            # Keyword call - pop kwargs dict then args
            self._emit_kw_call(arg)

        elif op == "CALL_METHOD":
            self._emit_method_call(arg)

        # Binary operations
        elif op == "BINARY_OP":
            self._emit_binary_op(arg)

        elif op == "UNARY_NOT" and self.stack:
            val = self.stack.pop()
            self.stack.append(f"not {val}")

        # Comparison
        elif op == "COMPARE_OP":
            self._emit_compare(arg)

        elif op == "CONTAINS_OP":
            if len(self.stack) >= 2:
                obj = self.stack.pop()
                container = self.stack.pop() if self.stack else "_"
                if arg == 1:  # not in
                    self.stack.append(f"{obj} not in {container}")
                else:
                    self.stack.append(f"{obj} in {container}")

        # Building containers
        elif op == "BUILD_TUPLE":
            self._emit_build_tuple(arg)

        elif op == "BUILD_LIST":
            self._emit_build_list(arg)

        elif op == "BUILD_DICT":
            self._emit_build_dict(arg)

        elif op == "BUILD_SET":
            self._emit_build_set(arg)

        elif op == "BUILD_SLICE":
            self._emit_build_slice(arg)

        # Subscript operations
        elif op == "BINARY_SUBSCR" or op == "SUBSCR":
            if len(self.stack) >= 2:
                idx = self.stack.pop()
                obj = self.stack.pop() if self.stack else "_"
                self.stack.append(f"{obj}[{idx}]")

        elif op == "STORE_SUBSCR":
            # stack: [container, index, value] -> container[index] = value
            if len(self.stack) >= 3:
                val = self.stack.pop()  # TOS = value
                idx = self.stack.pop()  # TOS1 = index
                obj = self.stack.pop()  # TOS2 = container
                self.statements.append(f"{obj}[{idx}] = {val}")

        # Return
        elif op == "RETURN_VALUE":
            if self.stack:
                val = self.stack.pop()
                if val != "None":
                    self.statements.append(f"return {val}")

        # Raises
        elif op == "RAISE_VARARGS":
            if arg == 0:
                self.statements.append("raise")
            elif self.stack:
                exc = self.stack.pop()
                self.statements.append(f"raise {exc}")

        # Jumps (simplified)
        elif op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE"):
            if self.stack:
                cond = self.stack.pop()
                self.statements.append(f"if {cond}:")
                self.statements.append("    pass")

        elif op == "FOR_ITER":
            self.statements.append("for _ in _:")
            self.statements.append("    pass")
            self.stack.clear()

        # Cleanup operations
        elif op in ("POP_TOP", "ROT_TWO", "ROT_THREE", "ROT_FOUR", "SWAP"):
            if self.stack:
                self.stack.pop()

    def _get_varname(self, arg: int | None) -> str:
        if arg is None:
            return "_"
        if arg < len(self.code.co_varnames):
            return self.code.co_varnames[arg]
        return f"var_{arg}"

    def _get_name(self, arg: int | None) -> str:
        if arg is None:
            return "_"
        # For LOAD_GLOBAL, arg is shifted
        idx = arg >> 1 if arg else arg
        if idx is not None and idx < len(self.code.co_names):
            return self.code.co_names[idx]
        if arg is not None and arg < len(self.code.co_names):
            return self.code.co_names[arg]
        return f"name_{arg}"

    def _format_const(self, arg: int | None) -> str:
        if arg is None or arg >= len(self.code.co_consts):
            return "None"
        c = self.code.co_consts[arg]
        if c is None:
            return "None"
        if c is Ellipsis:
            return "..."
        if isinstance(c, bool):
            return "True" if c else "False"
        if isinstance(c, str):
            escaped = c.replace("'", "\\'").replace("\\", "\\\\").replace("\n", "\\n")
            return f"'{escaped}'"
        if isinstance(c, bytes):
            try:
                decoded = c[:20].decode('utf-8', errors='replace')
                return f"b'{decoded}...'"
            except:
                return f"b'{c[:20].hex()}...'"
        if isinstance(c, (int, float)):
            return str(c)
        if isinstance(c, tuple):
            items = [repr(x) if isinstance(x, (int, str, float, bool)) else str(x)[:30] for x in c]
            return f"({', '.join(items)},)" if len(c) == 1 else f"({', '.join(items)})"
        if isinstance(c, types.CodeType):
            return f"<code:{c.co_name}>"
        return repr(c)[:50]

    def _emit_call(self, argc: int | None):
        """Emit a function call."""
        if argc is None:
            argc = 0

        args = []
        for _ in range(min(argc, len(self.stack))):
            args.insert(0, self.stack.pop())

        if self.stack:
            func = self.stack.pop()
            # Clean up the function name
            if " + NULL" in func:
                func = func.split(" + NULL")[0]
            if " + NULL|" in func:
                func = func.split(" + NULL|")[0]

            args_str = ", ".join(args)
            call_str = f"{func}({args_str})"
            self.stack.append(call_str)
        else:
            self.stack.append(f"call({', '.join(args)})")

    def _emit_kw_call(self, argc: int | None):
        """Emit a function call with keyword arguments.

        CALL_KW stack layout (bottom to top):
            [func, pos_arg1, ..., pos_argN, kw_val1, ..., kw_valM, tuple_of_kw_names]
            argc = N + M (total args including keyword values)
        """
        if argc is None:
            argc = 0

        # Pop keyword names tuple (top of stack)
        kw_names = self.stack.pop() if self.stack else "()"

        # Parse keyword names tuple like "('role',)" -> ['role']
        kw_names_list = []
        if kw_names and kw_names.startswith("(") and kw_names.endswith(")"):
            inner = kw_names[1:-1]
            if inner.endswith(","):
                inner = inner[:-1]
            if inner:
                kw_names_list = [x.strip().strip("'") for x in inner.split(",")]

        num_kwargs = len(kw_names_list)
        num_posargs = argc - num_kwargs

        # Pop keyword values
        kwargs = {}
        for i in range(min(num_kwargs, len(self.stack))):
            val = self.stack.pop()
            name = kw_names_list[num_kwargs - 1 - i] if i < len(kw_names_list) else f"kw_{i}"
            kwargs[name] = val

        # Pop positional args
        args = []
        for _ in range(min(num_posargs, len(self.stack))):
            args.insert(0, self.stack.pop())

        # Pop function
        func = self.stack.pop() if self.stack else "_"
        if " + NULL" in func:
            func = func.split(" + NULL")[0]

        # Build call string
        arg_strs = args
        kw_strs = [f"{k}={v}" for k, v in kwargs.items()]
        all_args = arg_strs + kw_strs
        call_str = f"{func}({', '.join(all_args)})"
        self.stack.append(call_str)

    def _emit_method_call(self, argc: int | None):
        """Emit a method call."""
        if argc is None:
            argc = 0

        args = []
        for _ in range(min(argc, len(self.stack))):
            args.insert(0, self.stack.pop())

        if self.stack:
            method = self.stack.pop()
            args_str = ", ".join(args)
            self.stack.append(f"{method}({args_str})")
        else:
            self.stack.append(f".method({', '.join(args)})")

    def _emit_binary_op(self, arg: int | None):
        if len(self.stack) < 2:
            return
        right = self.stack.pop()
        left = self.stack.pop()
        op = self.binops.get(arg, "+")
        self.stack.append(f"({left} {op} {right})")

    def _emit_compare(self, arg: int | None):
        if len(self.stack) < 2:
            return
        right = self.stack.pop()
        left = self.stack.pop()
        cmp = self.cmps.get(arg, "==")
        self.stack.append(f"({left} {cmp} {right})")

    def _emit_build_tuple(self, count: int | None):
        if count is None:
            count = 0
        items = []
        for _ in range(min(count, len(self.stack))):
            items.insert(0, self.stack.pop())
        if len(items) == 1:
            self.stack.append(f"({items[0]},)")
        else:
            self.stack.append(f"({', '.join(items)})")

    def _emit_build_list(self, count: int | None):
        if count is None:
            count = 0
        items = []
        for _ in range(min(count, len(self.stack))):
            items.insert(0, self.stack.pop())
        self.stack.append(f"[{', '.join(items)}]")

    def _emit_build_dict(self, count: int | None):
        if count is None:
            count = 0
        pairs = []
        for _ in range(min(count, len(self.stack) // 2)):
            if len(self.stack) >= 2:
                v = self.stack.pop()
                k = self.stack.pop()
                pairs.insert(0, f"{k}: {v}")
        self.stack.append(f"{{{', '.join(pairs)}}}")

    def _emit_build_set(self, count: int | None):
        if count is None:
            count = 0
        items = []
        for _ in range(min(count, len(self.stack))):
            items.insert(0, self.stack.pop())
        self.stack.append(f"{{{', '.join(items)}}}")

    def _emit_build_slice(self, argc: int | None):
        if argc == 2:
            stop = self.stack.pop() if self.stack else ""
            start = self.stack.pop() if self.stack else ""
            self.stack.append(f"{start}:{stop}")
        elif argc == 3:
            step = self.stack.pop() if self.stack else ""
            stop = self.stack.pop() if self.stack else ""
            start = self.stack.pop() if self.stack else ""
            self.stack.append(f"{start}:{stop}:{step}")


def _emit_ir(node: IRNode, indent: int = 0) -> str:
    """Emit Python source from IR."""
    prefix = "    " * indent
    lines = []

    if node.ir_type == IRType.MODULE:
        for imp in node.imports:
            lines.append(imp)
        if node.imports:
            lines.append("")

        for i, child in enumerate(node.children):
            lines.append(_emit_ir(child, indent))
            if i < len(node.children) - 1:
                lines.append("")

    elif node.ir_type == IRType.CLASS:
        for dec in node.decorators:
            lines.append(f"@{dec}")
        lines.append(f"class {node.name}:")

        if node.children:
            for child in node.children:
                lines.append(_emit_ir(child, indent + 1))
        else:
            lines.append(f"{prefix}    pass")

    elif node.ir_type == IRType.FUNCTION:
        for dec in node.decorators:
            lines.append(f"@{dec}")
        args_str = ", ".join(node.args) if node.args else ""
        lines.append(f"def {node.name}({args_str}):")

        has_content = False

        # Nested definitions
        for child in node.children:
            lines.append(_emit_ir(child, indent + 1))
            has_content = True

        # Function body
        if node.body:
            for stmt in node.body:
                if stmt.strip():
                    lines.append(f"{prefix}    {stmt}")
                    has_content = True

        if not has_content:
            lines.append(f"{prefix}    pass")

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

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DecompileResult:
    success: bool
    output_path: Path | None
    message: str


class Decompiler:
    PYLINGUAL_PATH = Path("references/bytecode_decompiler")

    @staticmethod
    def decompile(
        pyc_path: Path, output_dir: Path | None = None, version: str | None = None
    ) -> DecompileResult:
        if not pyc_path.exists():
            return DecompileResult(False, None, "File not found")

        pylingual_path = Decompiler.PYLINGUAL_PATH
        if not pylingual_path.exists():
            return DecompileResult(False, None, "PyLingual not found in references/")

        try:
            cmd = [sys.executable, "-m", "pylingual", str(pyc_path)]

            if output_dir:
                cmd.extend(["-o", str(output_dir)])

            if version:
                cmd.extend(["-v", version])

            result = subprocess.run(
                cmd,
                cwd=str(pylingual_path),
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                out_file = pyc_path.with_suffix(".py")
                if output_dir:
                    out_file = output_dir / f"decompiled_{pyc_path.name[:-4]}.py"
                return DecompileResult(True, out_file, "Decompilation successful")
            else:
                return DecompileResult(False, None, result.stderr or "Decompilation failed")
        except Exception as e:
            return DecompileResult(False, None, str(e))

    @staticmethod
    def decompile_directory(directory: Path, version: str | None = None) -> int:
        count = 0
        for pyc_path in directory.rglob("*.pyc"):
            result = Decompiler.decompile(pyc_path, version=version)
            if result.success:
                count += 1
        return count

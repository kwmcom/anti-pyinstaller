import sys
from pathlib import Path

from src import detector, disasm, extractor, pyc_fixer, logger


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    if verbose:
        sys.argv = [a for a in sys.argv if a not in ("-v", "--verbose")]
        logger.set_verbose(True)

    if len(sys.argv) < 2:
        print("Usage: anti-pyinstaller <command> <args>")
        print("Commands: detect, extract, disassemble, dis")
        print("Options: -v, --verbose")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "detect":
        if len(sys.argv) < 3:
            print("Usage: detect <file>")
            sys.exit(1)
        file = Path(sys.argv[2])
        info = detector.detect(file)
        if info is None:
            sys.exit(1)
        print(
            f"PyInstaller {info.version}, Python {info.python_version[0]}.{info.python_version[1]}"
        )
        print(f"Platform: {info.platform}")
        print(f"Files: {info.file_count}")
        if info.is_encrypted:
            print("Warning: encrypted")

    elif cmd == "extract":
        if len(sys.argv) < 3:
            print("Usage: extract <file>")
            sys.exit(1)
        file = Path(sys.argv[2])
        result = extractor.extract(file, None)
        if not result.success:
            logger.error(result.message)
            sys.exit(1)
        print(f"Extracted to {result.output_dir}")
        pyc_fixer.fix_directory(result.output_dir)
        disasm.disassemble_directory(result.output_dir)

    elif cmd == "disassemble":
        if len(sys.argv) < 3:
            print("Usage: disassemble <dir>")
            sys.exit(1)
        dir = Path(sys.argv[2])
        pyc_fixer.fix_directory(dir)
        disasm.disassemble_directory(dir)

    elif cmd == "dis":
        if len(sys.argv) < 3:
            print("Usage: dis <file.pyc>")
            sys.exit(1)
        file = Path(sys.argv[2])
        pyc_fixer.fix_pyc(file)
        result = disasm.disassemble(file)
        if result.success:
            print(f"Written to {result.output_path}")
        else:
            logger.error(result.message)
            sys.exit(1)

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()

import sys
from pathlib import Path

from src import detector, disasm, extractor, pyc_fixer, logger, reconstruct


def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    if verbose:
        sys.argv = [a for a in sys.argv if a not in ("-v", "--verbose")]
        logger.set_verbose(True)

    if len(sys.argv) < 2:
        print("Usage: anti-pyinstaller <command> <args>")
        print("Commands: detect, extract, disassemble, dis, pseudo")
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

    elif cmd == "auto":
        logger.set_verbose(True)
        if len(sys.argv) < 3:
            print("Usage: auto <file>")
            sys.exit(1)
        file = Path(sys.argv[2])
        # Extract
        result = extractor.extract(file, None)
        if not result.success:
            logger.error(result.message)
            sys.exit(1)
        
        output_dir = result.output_dir
        logger.info(f"Entry point extracted to: {output_dir}")
        
        # Decide scope
        print("\nChoose processing scope:")
        print("1. Entry Point Only")
        print("2. All Files")
        choice = input("Enter choice (1/2): ").strip()
        
        # Identify entry point
        pyc_files = list(output_dir.rglob("*.pyc"))
        
        if choice == "1":
            # Search for potential entry point files
            entry_points = [f for f in pyc_files if f.stem == file.stem]
            if not entry_points:
                # If no direct match, try looking for the most likely main file
                # PyInstaller typically puts the main script in the root of the extract
                potential_entries = [f for f in pyc_files if f.parent == output_dir]
                if potential_entries:
                    entry_points = potential_entries
            
            if entry_points:
                pyc_files = entry_points
                logger.info(f"Filtering to {len(pyc_files)} potential entry point(s)")
            else:
                logger.warning("Could not identify specific entry point, defaulting to all files.")
        
        # Setup directories
        dis_dir = output_dir / "disassembled"
        dis_dir.mkdir(exist_ok=True)
        recon_dir = output_dir / "reconstructed"
        recon_dir.mkdir(exist_ok=True)
        
        # Process files
        logger.info(f"Found {len(pyc_files)} pyc file(s) to process")
        
        for i, pyc_file in enumerate(pyc_files):
            logger.info(f"Processing ({i+1}/{len(pyc_files)}): {pyc_file.name}")
            
            # Disassemble
            dis_output = dis_dir / pyc_file.with_suffix(".txt").name
            dis_res = disasm.disassemble(pyc_file, output_path=dis_output)
            if not dis_res.success:
                logger.warning(f"Failed to disassemble {pyc_file.name}: {dis_res.message}")
            
            # Reconstruct
            pyc_fixer.fix_pyc(pyc_file)
            recon_res = reconstruct.reconstruct(pyc_file)
            if recon_res.success and recon_res.output_path and recon_res.output_path.exists():
                import shutil
                dest = recon_dir / recon_res.output_path.name
                shutil.copy2(str(recon_res.output_path), str(dest))
            else:
                logger.warning(f"Failed to reconstruct {pyc_file.name}: {recon_res.message if hasattr(recon_res, 'message') else 'Unknown error'}")
        
        logger.info(f"Disassembled files in: {dis_dir}")
        logger.info(f"Reconstructed files in: {recon_dir}")

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

    elif cmd in ("pseudo", "reconstruct"):
        if len(sys.argv) < 3:
            print("Usage: pseudo <file.pyc>")
            sys.exit(1)
        file = Path(sys.argv[2])
        pyc_fixer.fix_pyc(file)
        result = reconstruct.reconstruct(file)
        if result.success:
            print(f"Reconstructed to {result.output_path}")
        else:
            logger.error(result.message)
            sys.exit(1)

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()

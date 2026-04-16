# anti-pynstaller

Automated PyInstaller executable extractor and disassembler.

## Overview

anti-pynstaller identifies PyInstaller executables (Windows .exe and Linux ELF), extracts their contents, fixes PYC file headers, and disassembles the bytecode using Python's built-in `dis` module.

## Requirements

- Python 3.12+

## Installation

```bash
pip install -e .
```

## Usage

### Extract and disassemble a PyInstaller executable

```bash
anti-pynstaller extract myapp.exe
```

Options:
- `-o, --output`: Output directory
- `--no-disasm`: Only extract, skip disassembly

### Detect if a file is a PyInstaller executable

```bash
anti-pynstaller detect myapp.exe
```

### Disassemble all .pyc files in a directory

```bash
anti-pynstaller disassemble extracted_dir/
```

### Disassemble a single .pyc file

```bash
anti-pynstaller disassemble-one myapp.pyc
```

## Project Structure

```
anti_pynstaller/
├── __init__.py      # CLI entry point
├── detector.py      # PyInstaller binary detection
├── extractor.py     # Archive extraction
├── pyc_fixer.py     # PYC header fixing
└── disasm.py        # Bytecode disassembly (using built-in dis)
```

## Zero-Dependency Design

- **detector.py**: Pure Python - identifies PyInstaller binaries by MEI magic bytes
- **extractor.py**: Pure Python - extracts CArchive from PE/ELF without external libs
- **pyc_fixer.py**: Pure Python - fixes PYC headers for decompilers
- **disasm.py**: Uses Python's built-in `dis` module - zero external dependencies

The only runtime dependency is `click` for CLI argument parsing. All core functionality uses only Python standard library.

## License

MIT License
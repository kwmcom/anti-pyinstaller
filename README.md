# anti-pynstaller

Zero-dependency PyInstaller executable extractor and disassembler.

## Features

- **Detect** - Identify PyInstaller binaries, show version, Python version, file count
- **Extract** - Extract CArchive and PYZ contents with proper directory structure  
- **Fix** - Reconstruct valid .pyc headers (8/12/16 byte variants)
- **Disassemble** - Bytecode disassembly using Python's built-in `dis` module

## Requirements

- Python 3.12+
- click (CLI only)

## Install

```bash
pip install --break-system-packages -e .
```

## Usage

```bash
# Detect and show info
anti-pynstaller detect myapp.exe

# Extract archive
anti-pynstaller extract myapp.exe

# Disassemble directory
anti-pynstaller disassemble extracted_dir/

# Disassemble single file
anti-pynstaller disassemble-one myapp.pyc
```

## Design

- Zero external dependencies (stdlib only + click)
- Clean implementation - no code copied from references
- Supports Windows .exe and Linux ELF

## License

MIT
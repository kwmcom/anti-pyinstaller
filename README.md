# anti-pynstaller

PyInstaller extractor and disassembler.

## Install

```bash
pip install -e .
```

## Usage

```bash
anti-pynstaller detect file.exe     # Show info
anti-pynstaller extract file.exe     # Extract archive
anti-pynstaller disassemble dir/     # Disassemble all .pyc
anti-pynstaller dis file.pyc         # Disassemble one .pyc
```

Zero dependencies (stdlib only).
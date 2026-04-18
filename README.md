# Anti-PyInstaller

A lightweight, dependency-free tool for analyzing, extracting, and deconstructing PyInstaller-packed executables.

## Getting Started

### Installation
Clone the repository and install the package:

```bash
git clone https://github.com/kwmcom/anti-pyinstaller.git
cd anti-pyinstaller
pip install -e .
```

## Usage

You can run commands using `anti-pynstaller <command> <target>`:

*   **`detect <file>`**: Inspects a binary to see if it is PyInstaller-packed and displays information like Python version and platform.
*   **`extract <file>`**: Unpacks the contents of the PyInstaller archive into an `_extracted` folder.
*   **`auto <file>`**: **All-in-one analysis**. Extracts the binary, then automatically disassembles and reconstructs the `.pyc` files found. You can choose to process only the main entry point or everything at once.
*   **`disassemble <directory>`**: Processes all `.pyc` files in a folder, converting them into readable text-based disassembly files.
*   **`dis <file.pyc>`**: Disassembles a single `.pyc` file.
*   **`pseudo <file.pyc>`**: Attempts to reconstruct the source code from a `.pyc` file.

## Why use Anti-PyInstaller?
*   **Zero Dependencies**: Uses only Python's standard library.
*   **Detailed**: Provides both low-level bytecode disassembly and high-level pseudocode reconstruction.
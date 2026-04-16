import sys
from pathlib import Path

import click

from anti_pynstaller import detector
from anti_pynstaller import disasm
from anti_pynstaller import extractor
from anti_pynstaller import pyc_fixer


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """anti-pynstaller - PyInstaller extractor and disassembler"""
    pass


@cli.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
def detect(input_file: Path):
    """Detect and show info about a PyInstaller executable"""
    info = detector.detect(input_file)

    if info is None:
        click.echo("[-] Not a PyInstaller executable")
        sys.exit(1)

    click.echo("[+] PyInstaller binary detected")
    click.echo(f"[+] PyInstaller version: {info.version}")
    click.echo(f"[+] Python version: {info.python_version[0]}.{info.python_version[1]}")
    click.echo(f"[+] Platform: {info.platform}")
    click.echo(f"[+] Files in archive: {info.file_count}")

    if info.entry_point:
        click.echo(f"[+] Entry point: {info.entry_point}")

    if info.is_encrypted:
        click.echo("[!] Warning: Encrypted archive detected - extraction may be incomplete")


@cli.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    "output_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory",
)
@click.option("--no-disasm", is_flag=True, help="Skip disassembly")
def extract(input_file: Path, output_dir: Path | None, no_disasm: bool):
    """Extract contents from a PyInstaller executable"""
    info = detector.detect(input_file)

    if info is None:
        click.echo("[-] Not a PyInstaller executable", err=True)
        sys.exit(1)

    click.echo(f"[+] Extracting {input_file.name}...")

    result = extractor.extract(input_file, output_dir)

    if not result.success:
        click.echo(f"[-] {result.message}", err=True)
        sys.exit(1)

    click.echo(f"[+] Extracted {result.info.file_count} files to {result.output_dir}")

    if result.info.entry_point:
        click.echo(f"[+] Entry point: {result.info.entry_point}")

    if result.info.encrypted:
        click.echo("[!] Encrypted archive - some files may not extract")

    fixed = pyc_fixer.fix_directory(result.output_dir)
    click.echo(f"[+] Fixed {fixed} .pyc headers")

    if not no_disasm:
        count = disasm.disassemble_directory(result.output_dir)
        click.echo(f"[+] Disassembled {count} files")


@cli.command()
@click.argument("directory", type=click.Path(exists=True, path_type=Path))
def disassemble(directory: Path):
    """Disassemble all .pyc files in a directory"""
    fixed = pyc_fixer.fix_directory(directory)
    click.echo(f"[+] Fixed {fixed} .pyc headers")

    count = disasm.disassemble_directory(directory)
    click.echo(f"[+] Disassembled {count} files")


@cli.command()
@click.argument("pyc_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    "output_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Output .py file",
)
def disassemble_one(pyc_file: Path, output_file: Path | None):
    """Disassemble a single .pyc file"""
    pyc_fixer.fix_pyc(pyc_file)

    result = disasm.disassemble(pyc_file, output_file)

    if result.success:
        click.echo(f"[+] Disassembled to: {result.output_path}")
    else:
        click.echo(f"[-] {result.message}", err=True)
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()

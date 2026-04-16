import sys
from pathlib import Path

import click

from anti_pynstaller import detector, disasm, extractor, pyc_fixer


@click.group()
@click.version_option(version="1.0.0")
def cli():
    pass


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
def detect(file: Path):
    """Show PyInstaller info."""
    info = detector.detect(file)
    if info is None:
        click.echo("Not a PyInstaller executable")
        sys.exit(1)
    click.echo(
        f"PyInstaller {info.version}, Python {info.python_version[0]}.{info.python_version[1]}"
    )
    click.echo(f"Platform: {info.platform}")
    click.echo(f"Files: {info.file_count}")
    if info.encrypted:
        click.echo("Warning: encrypted")


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--output", "output_dir", type=click.Path(path_type=Path))
def extract(file: Path, output_dir: Path | None):
    """Extract PyInstaller archive."""
    result = extractor.extract(file, output_dir)
    if not result.success:
        click.echo(f"Error: {result.message}")
        sys.exit(1)
    click.echo(f"Extracted to {result.output_dir}")
    pyc_fixer.fix_directory(result.output_dir)
    disasm.disassemble_directory(result.output_dir)


@cli.command()
@click.argument("dir", type=click.Path(exists=True, path_type=Path))
def disassemble(dir: Path):
    """Disassemble all .pyc files."""
    pyc_fixer.fix_directory(dir)
    disasm.disassemble_directory(dir)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
def dis(file: Path):
    """Disassemble a .pyc file."""
    pyc_fixer.fix_pyc(file)
    result = disasm.disassemble(file)
    if result.success:
        click.echo(f"Written to {result.output_path}")
    else:
        click.echo(f"Error: {result.message}")
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()

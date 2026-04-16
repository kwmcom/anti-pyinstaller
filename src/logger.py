import sys

VERBOSE = False


def set_verbose(v: bool):
    global VERBOSE
    VERBOSE = v


def debug(msg: str):
    if VERBOSE:
        print(f"[DEBUG] {msg}", file=sys.stderr)


def info(msg: str):
    print(f"[INFO] {msg")


def warn(msg: str):
    print(f"[WARN] {msg}", file=sys.stderr)


def warning(msg: str):
    print(f"[WARN] {msg}", file=sys.stderr)


def error(msg: str):
    print(f"[ERROR] {msg}", file=sys.stderr)


def fatal(msg: str):
    print(f"[FATAL] {msg}", file=sys.stderr)
    sys.exit(1)

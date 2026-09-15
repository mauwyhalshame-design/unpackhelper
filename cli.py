import argparse
from pathlib import Path
from signatures import SIGNATURES

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="unpackhelper", description="Static PE packer fingerprinting; never executes analyzed files.")
    parser.add_argument("--version", action="version", version="UnpackHelper 1.0.0")
    parser.add_argument("--config", help="Optional JSON configuration file")
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Analyze one PE file")
    scan.add_argument("file", type=Path)
    scan.add_argument("--json", action="store_true", help="Print JSON output")
    scan.add_argument("--output", type=Path, help="Save JSON report to a file")
    scan.add_argument("--html", type=Path, help="Save a standalone HTML report to a file")
    folder = sub.add_parser("scan-dir", help="Analyze all files in a folder")
    folder.add_argument("folder", type=Path)
    folder.add_argument("--no-recursive", action="store_true", help="Do not scan subdirectories")
    folder.add_argument("--json", action="store_true", help="Print JSON output")
    folder.add_argument("--output", type=Path, help="Save JSON output to a file")
    folder.add_argument("--html", type=Path, help="Save an HTML report to a file")
    compare = sub.add_parser("compare", help="Compare two files by SHA-256")
    compare.add_argument("file1", type=Path)
    compare.add_argument("file2", type=Path)
    sub.add_parser("signatures", help="List built-in packer signatures")
    return parser

def print_signatures() -> None:
    for name, rule in SIGNATURES.items():
        sections = ", ".join(rule["sections"]) or "contextual marker only"
        print(f"{name}: {sections}")

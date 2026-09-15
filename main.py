import logging
import sys
from typing import Iterable, Optional

from cli import build_parser, print_signatures
from compare import compare_files
from config import load_config
from errors import AnalysisError
from fingerprint import fingerprint
from folder_scan import scan_folder
from html_report import write_folder_html, write_html
from pe_parser import parse_pe
from report import build_result, render_compare_text, render_folder_text, render_json, render_text


def _write_json(path, result: dict) -> None:
    try:
        path.write_text(render_json(result) + "\n", encoding="utf-8")
    except OSError as exc:
        raise AnalysisError(f"تعذر حفظ التقرير: {exc}") from exc


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s: %(message)s")
    try:
        config = load_config(args.config)
        if args.command == "signatures":
            print_signatures()
            return 0
        if args.command == "scan":
            if args.output and not args.json:
                raise AnalysisError("خيار --output يحتاج إلى استخدام --json")
            if args.html and (args.json or args.output):
                raise AnalysisError("استخدم --html منفردًا عن --json و--output")
            info = parse_pe(args.file, max_size=config["max_file_size"])
            result = build_result(info, fingerprint(info))
            if args.output:
                _write_json(args.output, result)
                print(f"Report saved: {args.output}")
            elif args.html:
                write_html(result, args.html)
                print(f"HTML report saved: {args.html}")
            else:
                print(render_json(result) if args.json else render_text(result))
            return 0
        if args.command == "scan-dir":
            if args.output and not args.json:
                raise AnalysisError("خيار --output يحتاج إلى استخدام --json")
            if args.html and (args.json or args.output):
                raise AnalysisError("استخدم --html منفردًا عن --json و--output")
            result = scan_folder(args.folder, config["max_file_size"], recursive=not args.no_recursive)
            if args.output:
                _write_json(args.output, result)
                print(f"Report saved: {args.output}")
            elif args.html:
                write_folder_html(result, args.html)
                print(f"HTML report saved: {args.html}")
            else:
                print(render_json(result) if args.json else render_folder_text(result))
            return 0
        if args.command == "compare":
            print(render_compare_text(compare_files(args.file1, args.file2)))
            return 0
        parser.print_help()
        return 0
    except AnalysisError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception:
        logging.getLogger("unpackhelper").exception("Unexpected failure")
        print("Error: unexpected internal failure", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

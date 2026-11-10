import argparse
from importlib.resources import files
import os
from pathlib import Path
import sys
import tempfile

from . import __version__
from .core import compare, load
from .report import render


def _options(parser):
    parser.add_argument("--output", type=Path, help="report file; defaults to stdout")
    parser.add_argument("--format", choices=("json", "markdown", "html"), help="defaults from output extension, otherwise JSON")
    parser.add_argument("--deny-license", action="append", default=[], metavar="ID", help="reject this exact license identifier/name anywhere in the current inventory")
    parser.add_argument("--deny-new", action="store_true", help="reject newly introduced component identities")
    parser.add_argument("--deny-unknown-license", action="store_true")
    parser.add_argument("--deny-ambiguous", action="store_true")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review standard SBOM changes with explicit release policy")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    commands = parser.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("compare", help="compare a baseline and current SBOM")
    cmd.add_argument("baseline", type=Path)
    cmd.add_argument("current", type=Path)
    _options(cmd)
    _options(commands.add_parser("demo", help="compare bundled synthetic CycloneDX release fixtures"))
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            root = files("sbom_change_review").joinpath("fixtures")
            baseline, current = root.joinpath("before.cdx.json"), root.joinpath("after.cdx.json")
        else:
            baseline, current = args.baseline, args.current
        if args.output and args.output.resolve() in {Path(str(baseline)).resolve(), Path(str(current)).resolve()}:
            raise ValueError("output must not overwrite an input SBOM")
        report = compare(load(baseline), load(current), args.deny_license, args.deny_new, args.deny_unknown_license, args.deny_ambiguous)
        fmt = args.format or ({".html": "html", ".htm": "html", ".md": "markdown"}.get(args.output.suffix.lower(), "json") if args.output else "json")
        payload = render(report, fmt)
        if args.output:
            # Write atomically so a failed report cannot destroy an old report.
            temp_name = None
            try:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=args.output.parent, delete=False) as handle:
                    temp_name = handle.name
                    handle.write(payload)
                os.replace(temp_name, args.output)
            finally:
                if temp_name and os.path.exists(temp_name):
                    os.unlink(temp_name)
        else:
            print(payload, end="")
        return 0 if report["passed"] else 1
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

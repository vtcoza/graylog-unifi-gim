from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pack import build_all
from .parser import parse_message
from .sanitizer import sanitize_message


def main() -> int:
    parser = argparse.ArgumentParser(prog="unifi-gim")
    commands = parser.add_subparsers(dest="command", required=True)
    parse = commands.add_parser("parse", help="Parse one raw message")
    parse.add_argument("message")
    sanitize = commands.add_parser("sanitize", help="Sanitize one raw message")
    sanitize.add_argument("message")
    build = commands.add_parser("build", help="Build both content packs")
    build.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if args.command == "parse":
        print(json.dumps(parse_message(args.message), indent=2, sort_keys=True))
    elif args.command == "sanitize":
        print(sanitize_message(args.message))
    else:
        for output in build_all(args.root):
            print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

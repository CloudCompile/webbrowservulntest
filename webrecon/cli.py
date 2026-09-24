#!/usr/bin/env python3
"""webrecon CLI - static WebView reconnaissance for Android apps.

Examples
--------
  python -m webrecon.cli samples/apple_music.xapk -o out/apple_music
  python -m webrecon.cli app.apk -o out/app --skip-decompile   # reuse existing work dir
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import scanner
from . import report as report_mod


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="webrecon", description=__doc__)
    ap.add_argument("target", type=Path, help=".apk, .xapk or .apks file")
    ap.add_argument("-o", "--out", type=Path, required=True,
                    help="output directory (also used as decompile work dir)")
    ap.add_argument("--skip-decompile", action="store_true",
                    help="reuse an existing decompiled work dir at <out>/work")
    args = ap.parse_args(argv)

    if not args.target.exists():
        print(f"target not found: {args.target}", file=sys.stderr)
        return 2

    work = args.out / "work"
    rep = scanner.scan(args.target, work, skip_decompile=args.skip_decompile)

    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "report.json"
    md_path = args.out / "report.md"
    json_path.write_text(rep.to_json())
    md_path.write_text(report_mod.render(rep))

    print(f"package : {rep.package} {rep.version_name}")
    print(f"hosts   : {len(rep.hosts)} classes configure a WebView")
    counts = {}
    for f in rep.findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("findings: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"report  : {md_path}")
    print(f"json    : {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from qwen35_rag_utils import ROOT


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a compact parse summary report.")
    parser.add_argument("--parsed-dir", type=Path, default=ROOT / "outputs/parsed/feasibility")
    parser.add_argument("--report", type=Path, default=ROOT / "datasets/public/feasibility/metadata/feasibility_parse_report.md")
    args = parser.parse_args()

    summary_path = args.parsed_dir / "parse_all_summary.json"
    rows = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else []
    lines = [
        "# Feasibility parse report",
        "",
        f"- Parsed dir: `{args.parsed_dir.relative_to(ROOT) if args.parsed_dir.is_absolute() and ROOT in args.parsed_dir.parents else args.parsed_dir}`",
        f"- Parsed PCAP files: {len(rows)}",
        "",
        "| case_id | parser_source | zeek | tshark | session parser preference | errors | warnings |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        warnings = "; ".join(row.get("warnings", [])) or "none"
        errors = "; ".join(str(row.get(key) or "") for key in ("zeek_error", "tshark_error") if row.get(key)) or "none"
        lines.append(
            f"| {row.get('case_id')} | {row.get('parser_source')} | {row.get('zeek_success')} | {row.get('tshark_success')} | "
            f"{row.get('session_parser_preference', 'zeek_conn_then_zeek_docker_then_tshark_fallback')} | {errors} | {warnings} |"
        )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

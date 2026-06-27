#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from export_official_submission import export_official_submission


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if text:
                item = json.loads(text)
                if isinstance(item, dict):
                    rows.append(item)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def record_id(item: dict[str, Any]) -> str:
    return str(item.get("record_id") or item.get("session_id") or "")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge Phase-1 shard predictions and rebuild official submission files.")
    parser.add_argument("--shard-output-dir", type=Path, action="append", required=True, help="Shard output directory. Repeat once per shard.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Merged output directory.")
    parser.add_argument("--records-json", type=Path, required=True, help="Full selected_records.json from the unsharded/dry-run output.")
    parser.add_argument("--parse-summary", type=Path, help="parse_all_summary.json for pcap filename lookup.")
    parser.add_argument("--submission-template", type=Path)
    parser.add_argument("--submission-label-level", choices=["stage", "technique"], default="stage")
    parser.add_argument("--pcap-id-source", choices=["pcap_id", "pcap_name", "filename_stem"], default="pcap_id")
    parser.add_argument("--submission-timezone", choices=["UTC", "Asia/Shanghai"], default="Asia/Shanghai")
    parser.add_argument("--official-metadata-source", choices=["representative", "aggregate"], default="representative")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    records = load_json(args.records_json, [])
    if not isinstance(records, list):
        raise SystemExit(f"records-json must contain a JSON list: {args.records_json}")
    order = {record_id(record): index for index, record in enumerate(records) if record_id(record)}
    merged_by_id: dict[str, dict[str, Any]] = {}
    for shard_dir in args.shard_output_dir:
        for prediction in load_jsonl(shard_dir / "predictions.jsonl"):
            rid = record_id(prediction)
            if rid:
                merged_by_id[rid] = prediction
    merged = sorted(merged_by_id.values(), key=lambda item: order.get(record_id(item), 10**9))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = args.output_dir / "predictions.jsonl"
    write_jsonl(predictions_path, merged)
    stats = export_official_submission(
        predictions=merged,
        records_json=args.records_json,
        parse_summary=args.parse_summary,
        submission_template=args.submission_template,
        output_csv=args.output_dir / "official_submission.csv",
        output_xlsx=args.output_dir / "official_submission.xlsx",
        submission_label_level=args.submission_label_level,
        pcap_id_source=args.pcap_id_source,
        submission_timezone=args.submission_timezone,
        official_metadata_source=args.official_metadata_source,
    )
    print(json.dumps({"predictions": len(merged), **stats}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

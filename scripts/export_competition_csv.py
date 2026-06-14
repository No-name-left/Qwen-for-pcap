#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, load_json


STAGE_CODES = {"TA43", "TA01", "TA03", "TA11", "TN01"}
TECHNIQUE_CODES = {"TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"}
TECHNIQUE_TO_STAGE = {
    "TA43_01": "TA43",
    "TA43_02": "TA43",
    "TA01_01": "TA01",
    "TA01_02": "TA01",
    "TA03_01": "TA03",
    "TA11_01": "TA11",
    "TA11_02": "TA11",
    "TN01_01": "TN01",
}


def load_results(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    data = load_json(path)
    if isinstance(data, dict) and "results" in data:
        data = data["results"]
    if not isinstance(data, list):
        raise ValueError(f"result input must be a list: {path}")
    return data


def result_map(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("record_id") or item.get("session_id")): item for item in results}


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Export official competition CSV files from model results or dry-run records.")
    parser.add_argument("--records", type=Path, default=ROOT / "outputs/session_cards/classification_records_all.json")
    parser.add_argument("--stage-results", type=Path)
    parser.add_argument("--technique-results", type=Path)
    parser.add_argument("--stage-output", type=Path, default=ROOT / "outputs/submissions/stage1_submission.csv")
    parser.add_argument("--technique-output", type=Path, default=ROOT / "outputs/submissions/stage2_submission.csv")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/submissions/submission_export_report.md")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    records = load_json(args.records) if args.records.exists() else []
    stage_results = result_map(load_results(args.stage_results)) if args.stage_results else {}
    technique_results = result_map(load_results(args.technique_results)) if args.technique_results else {}
    dry_run = args.dry_run or (not stage_results and not technique_results)

    stage_rows: list[dict[str, Any]] = []
    technique_rows: list[dict[str, Any]] = []
    fallbacks: list[str] = []
    for record in records:
        rid = str(record.get("record_id") or record.get("session_id"))
        session_id = str(record.get("session_id") or rid)
        pcap_id = record.get("pcap_id")

        stage_code = "TN01"
        technique_code = "TN01_01"
        if not dry_run:
            stage_item = stage_results.get(rid, {})
            technique_item = technique_results.get(rid, {})
            stage_code = stage_item.get("predicted_code") or stage_item.get("stage_code") or stage_code
            technique_code = technique_item.get("predicted_code") or technique_item.get("technique_code") or technique_code
            if technique_code in TECHNIQUE_TO_STAGE and (not stage_item):
                stage_code = TECHNIQUE_TO_STAGE[technique_code]

        if stage_code not in STAGE_CODES:
            fallbacks.append(f"{rid}: invalid stage `{stage_code}` -> TN01")
            stage_code = "TN01"
        if technique_code not in TECHNIQUE_CODES:
            fallbacks.append(f"{rid}: invalid technique `{technique_code}` -> TN01_01")
            technique_code = "TN01_01"

        stage_rows.append({"pcap_id": pcap_id, "session_id": session_id, "stage_code": stage_code})
        technique_rows.append({"pcap_id": pcap_id, "session_id": session_id, "technique_code": technique_code})

    write_csv(args.stage_output, ["pcap_id", "session_id", "stage_code"], stage_rows)
    write_csv(args.technique_output, ["pcap_id", "session_id", "technique_code"], technique_rows)

    lines = [
        "# Submission export report",
        "",
        f"- Records input: `{args.records.relative_to(ROOT)}`",
        f"- Records exported: {len(records)}",
        f"- Stage CSV: `{args.stage_output.relative_to(ROOT)}`",
        f"- Technique CSV: `{args.technique_output.relative_to(ROOT)}`",
        f"- Dry-run placeholder: {str(dry_run).lower()}",
        "",
        "## Schema",
        "",
        "- Stage 1 fields: `pcap_id`, `session_id`, `stage_code`.",
        "- Stage 2 fields: `pcap_id`, `session_id`, `technique_code`.",
        "- CSV encoding: `utf-8-sig`.",
        "",
        "If the organizer's final template requires start time, end time, source IP, source port, destination IP, destination port, or judgment reason, those fields can be exported from `classification_records_all.json` plus model result JSON.",
        "",
        "## Fallbacks",
        "",
    ]
    if dry_run:
        lines.append("- CSV files are dry-run placeholders using `TN01` / `TN01_01`; they are not model results.")
    lines.extend(f"- {item}" for item in fallbacks) if fallbacks else lines.append("- none")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"exported {len(records)} rows per CSV")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

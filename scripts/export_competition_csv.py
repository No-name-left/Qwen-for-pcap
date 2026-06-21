#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from qwen35_rag_utils import ROOT, load_json


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


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


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
    technique_results = result_map(load_results(args.technique_results)) if args.technique_results else {}
    dry_run = args.dry_run

    validation_errors: list[str] = []
    if not dry_run:
        if not args.technique_results:
            validation_errors.append("--technique-results is required unless --dry-run is used")
        for record in records:
            rid = str(record.get("record_id") or record.get("session_id"))
            item = technique_results.get(rid)
            if not item:
                validation_errors.append(f"{rid}: missing technique result")
                continue
            technique_code = item.get("predicted_code") or item.get("technique_code")
            if technique_code not in TECHNIQUE_CODES:
                validation_errors.append(f"{rid}: invalid technique code `{technique_code}`")

    if validation_errors:
        lines = [
            "# Submission export report",
            "",
            "- Status: failed",
            "- Dry-run placeholder: false",
            f"- Records input: `{display_path(args.records)}`",
            f"- Technique results: `{args.technique_results}`",
            f"- Legacy stage results ignored: {str(bool(args.stage_results)).lower()}",
            "",
            "## Validation errors",
            "",
            *[f"- {error}" for error in validation_errors],
        ]
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"submission export failed with {len(validation_errors)} validation errors")
        return 2

    stage_rows: list[dict[str, Any]] = []
    technique_rows: list[dict[str, Any]] = []
    for record in records:
        rid = str(record.get("record_id") or record.get("session_id"))
        session_id = str(record.get("session_id") or rid)
        pcap_id = record.get("pcap_id")

        technique_code = "TN01_01" if dry_run else (
            technique_results[rid].get("predicted_code") or technique_results[rid].get("technique_code")
        )
        stage_code = TECHNIQUE_TO_STAGE[technique_code]

        stage_rows.append({"pcap_id": pcap_id, "session_id": session_id, "stage_code": stage_code})
        technique_rows.append({"pcap_id": pcap_id, "session_id": session_id, "technique_code": technique_code})

    write_csv(args.stage_output, ["pcap_id", "session_id", "stage_code"], stage_rows)
    write_csv(args.technique_output, ["pcap_id", "session_id", "technique_code"], technique_rows)

    lines = [
        "# Submission export report",
        "",
        f"- Records input: `{display_path(args.records)}`",
        f"- Records exported: {len(records)}",
        f"- Stage CSV: `{display_path(args.stage_output)}`",
        f"- Technique CSV: `{display_path(args.technique_output)}`",
        f"- Dry-run placeholder: {str(dry_run).lower()}",
        f"- Legacy stage results supplied and ignored: {str(bool(args.stage_results)).lower()}",
        "- Stage source: deterministic technique-to-stage mapping.",
        "",
        "## Schema",
        "",
        "- Stage 1 fields: `pcap_id`, `session_id`, `stage_code`.",
        "- Stage 2 fields: `pcap_id`, `session_id`, `technique_code`.",
        "- CSV encoding: `utf-8-sig`.",
        "",
        "If the organizer's final template requires start time, end time, source IP, source port, destination IP, destination port, or judgment reason, those fields can be exported from `classification_records_all.json` plus model result JSON.",
        "",
        "## Validation",
        "",
    ]
    if dry_run:
        lines.append("- CSV files are dry-run placeholders using `TN01` / `TN01_01`; they are not model results.")
    else:
        lines.append("- All records had a valid official technique code; no normal-class fallback was applied.")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"exported {len(records)} rows per CSV")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

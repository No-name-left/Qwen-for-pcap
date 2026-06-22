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
    "TA43_01": "TA43", "TA43_02": "TA43", "TA01_01": "TA01", "TA01_02": "TA01",
    "TA03_01": "TA03", "TA11_01": "TA11", "TA11_02": "TA11", "TN01_01": "TN01",
}
COMMON_FIELDS = ["pcap", "编号", "开始时间", "结束时间", "源IP", "源端口", "目的IP", "目的端口"]
REASON_FIELD = "研判理由（不计入评分）"
STAGE_LABEL_FIELD = "攻击阶段编号或正常流量编号"
TECHNIQUE_LABEL_FIELD = "攻击技术编号或正常流量编号"


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
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def first_present(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if record.get(key) not in (None, ""):
            return record[key]
    return ""


def stable_pcap_name(record: dict[str, Any]) -> str:
    value = first_present(record, "pcap", "pcap_file", "pcap_filename", "source_pcap", "original_pcap", "pcap_id")
    if isinstance(value, str) and ("/" in value or "\\" in value):
        return Path(value).name
    return str(value)


def official_row(record: dict[str, Any], result: dict[str, Any], code: str, label_field: str) -> dict[str, Any]:
    rid = str(first_present(record, "record_id", "session_id"))
    number = first_present(record, "编号", "number", "session_id", "record_id") or rid
    reason = result.get("reason") or record.get("reason") or ""
    return {
        "pcap": stable_pcap_name(record),
        "编号": number,
        "开始时间": first_present(record, "start_time", "开始时间"),
        "结束时间": first_present(record, "end_time", "结束时间"),
        "源IP": first_present(record, "src_ip", "源IP"),
        "源端口": first_present(record, "src_port", "源端口"),
        "目的IP": first_present(record, "dst_ip", "目的IP"),
        "目的端口": first_present(record, "dst_port", "目的端口"),
        label_field: code,
        REASON_FIELD: reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Export stage1 or stage2 official-layout CSV from technique-first results.")
    parser.add_argument("--records", type=Path, default=ROOT / "outputs/session_cards/classification_records_all.json")
    parser.add_argument("--stage-results", type=Path, help="Deprecated; ignored because stage is mapped from technique.")
    parser.add_argument("--technique-results", type=Path)
    parser.add_argument("--task-mode", choices=["stage1", "stage2", "both"], default="both")
    parser.add_argument("--output", type=Path, help="Single output path for stage1 or stage2 mode.")
    parser.add_argument("--stage-output", type=Path, default=ROOT / "outputs/submissions/stage1_submission.csv")
    parser.add_argument("--technique-output", type=Path, default=ROOT / "outputs/submissions/stage2_submission.csv")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/submissions/submission_export_report.md")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.output and args.task_mode == "both":
        parser.error("--output requires --task-mode stage1 or stage2")
    records = load_json(args.records) if args.records.exists() else []
    technique_results = result_map(load_results(args.technique_results)) if args.technique_results else {}
    errors: list[str] = []
    if not args.dry_run:
        if not args.technique_results:
            errors.append("--technique-results is required unless --dry-run is used")
        for record in records:
            rid = str(first_present(record, "record_id", "session_id"))
            item = technique_results.get(rid)
            code = (item or {}).get("predicted_code") or (item or {}).get("technique_code")
            if not item:
                errors.append(f"{rid}: missing technique result")
            elif code not in TECHNIQUE_CODES:
                errors.append(f"{rid}: invalid technique code `{code}`")
    if errors:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text("# Submission export report\n\n- Status: failed\n\n" + "\n".join(f"- {error}" for error in errors) + "\n", encoding="utf-8")
        print(f"submission export failed with {len(errors)} validation errors")
        return 2

    stage_rows: list[dict[str, Any]] = []
    technique_rows: list[dict[str, Any]] = []
    for record in records:
        rid = str(first_present(record, "record_id", "session_id"))
        result = {} if args.dry_run else technique_results[rid]
        technique = "TN01_01" if args.dry_run else result.get("predicted_code") or result.get("technique_code")
        stage_rows.append(official_row(record, result, TECHNIQUE_TO_STAGE[technique], STAGE_LABEL_FIELD))
        technique_rows.append(official_row(record, result, technique, TECHNIQUE_LABEL_FIELD))

    written: list[Path] = []
    if args.task_mode in {"stage1", "both"}:
        stage_path = args.output if args.task_mode == "stage1" and args.output else args.stage_output
        write_csv(stage_path, COMMON_FIELDS + [STAGE_LABEL_FIELD, REASON_FIELD], stage_rows)
        written.append(stage_path)
    if args.task_mode in {"stage2", "both"}:
        technique_path = args.output if args.task_mode == "stage2" and args.output else args.technique_output
        write_csv(technique_path, COMMON_FIELDS + [TECHNIQUE_LABEL_FIELD, REASON_FIELD], technique_rows)
        written.append(technique_path)

    lines = [
        "# Submission export report", "", "- Status: success", f"- Task mode: `{args.task_mode}`",
        f"- Records exported: {len(records)}", f"- Dry-run placeholder: {str(args.dry_run).lower()}",
        "- Internal prediction strategy: technique-first.", "- Stage source: deterministic technique-to-stage mapping.",
        "- CSV encoding: `utf-8-sig`.", f"- Legacy stage results supplied and ignored: {str(bool(args.stage_results)).lower()}", "",
        *[f"- Output: `{display_path(path)}`" for path in written], "",
        "Stage1 uses the organizer field order and stage label column. Stage2 preserves the same evidence columns and switches only the closed-set label column.",
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"exported {len(records)} rows for task_mode={args.task_mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Normalize existing trusted public labels into public-eval candidate records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TECHNIQUE_CODES = {"TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"}


def load_json_list(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"expected a JSON array of objects: {path}")
    return value


def clean_classification_record(record: dict[str, Any], record_type: str) -> dict[str, Any]:
    """Drop historical tool fields and keep evidence, not hidden labels."""
    forbidden = {
        "expected_technique_code", "expected_stage_code", "technique_code", "stage_code",
        "label_source", "label_quality", "mapping_confidence",
    }
    legacy_tool_marker = "".join(("suri", "cata"))
    cleaned = {
        key: value for key, value in record.items()
        if key not in forbidden and legacy_tool_marker not in key.lower()
    }
    cleaned["record_type"] = record_type
    return cleaned


def normalize_confidence(value: str) -> str:
    normalized = value.lower().strip()
    if normalized.startswith("high"):
        return "high"
    if normalized.startswith("medium"):
        return "medium"
    return "low"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build normalized candidate records from existing public-eval labels.")
    parser.add_argument("--labels", type=Path, default=ROOT / "outputs/eval_sets/small_coverage_test_set.json")
    parser.add_argument("--classification-records", type=Path, default=ROOT / "outputs/api_tests/zeek_eval/selected_records.json")
    parser.add_argument("--output", type=Path, default=ROOT / "datasets/public_eval/candidate_records.jsonl")
    args = parser.parse_args()
    labels = load_json_list(args.labels)
    source_records = {item["record_id"]: item for item in load_json_list(args.classification_records)}
    output: list[dict[str, Any]] = []
    missing: list[str] = []
    for label in labels:
        record_id = str(label.get("record_id", ""))
        code = label.get("expected_technique_code")
        if not record_id or code not in TECHNIQUE_CODES:
            raise ValueError(f"invalid label row: record_id={record_id!r}, technique_code={code!r}")
        source = source_records.get(record_id)
        if source is None:
            missing.append(record_id)
            continue
        is_flow = bool(label.get("flow_only")) or source.get("parser_source") == "flow_csv"
        record_type = "flow_only" if is_flow else str(source.get("record_type") or label.get("record_type") or "session")
        if record_type not in {"session", "scan_group", "flow_only"}:
            raise ValueError(f"unsupported record_type for {record_id}: {record_type}")
        confidence = normalize_confidence(str(label.get("mapping_confidence") or label.get("label_quality") or "low"))
        output.append({
            "record_id": record_id,
            "dataset_id": str(label.get("source_dataset") or source.get("pcap_id") or "unknown"),
            "source_file": str(label.get("source_file") or source.get("flow_source") or ""),
            "source_label": str(label.get("label_source") or ""),
            "technique_code": code,
            "label_confidence": confidence,
            "record_type": record_type,
            "pcap_id": str(source.get("pcap_id") or ""),
            "evidence_summary": str(label.get("why_trusted") or ""),
            "notes": str(label.get("limitations") or ""),
            "classification_record": clean_classification_record(source, record_type),
        })
    if missing:
        raise ValueError(f"missing classification evidence for {len(missing)} labels: {', '.join(missing[:5])}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in output), encoding="utf-8")
    counts: dict[str, int] = {}
    for item in output:
        key = f"{item['technique_code']}:{item['label_confidence']}:{item['record_type']}"
        counts[key] = counts.get(key, 0) + 1
    print(json.dumps({"output": str(args.output.relative_to(ROOT)), "records": len(output), "counts": counts}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

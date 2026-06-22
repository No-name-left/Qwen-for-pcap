#!/usr/bin/env python3
"""Evaluate paired no-RAG/RAG runner outputs without calling an API."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TECHNIQUE_CODES = ["TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"]
ERROR_CODE = "__ERROR__"
EVAL_SCOPES = (
    "strict external", "external_high_pcap", "external_high_flow", "external_medium",
    "external_low", "synthetic_controlled", "coverage all", "flow_only", "pcap/session-derived",
)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_runner_rows(result_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, str]]:
    results = load_json(result_dir / "results.json", [])
    result_map = {item.get("record_id"): item for item in results if isinstance(item, dict) and item.get("record_id")}
    stats = load_json(result_dir / "run_stats.json", {})
    status_map: dict[str, dict[str, Any]] = {}
    raw_map: dict[str, str] = {}
    for row in stats.get("rows", []):
        record_id = row.get("record_id")
        if not record_id:
            continue
        status_map[record_id] = row
        batch = row.get("batch")
        if isinstance(batch, int):
            raw_path = result_dir / "raw" / f"raw_batch_{batch:03d}.txt"
            if raw_path.exists():
                raw_map[record_id] = raw_path.read_text(encoding="utf-8", errors="replace")
            elif row.get("error"):
                raw_map[record_id] = ""
    return result_map, status_map, raw_map


def failure_type(status: dict[str, Any] | None) -> tuple[str, str]:
    if not status:
        return "missing", "missing_result"
    error = str(status.get("error") or "")
    low = error.lower()
    if "invalid technique code" in low:
        return "validation_failed", "illegal_code"
    if "json" in low or "no json object" in low:
        return "parse_failed", "json_parse_failure"
    return "failed", str(status.get("error_category") or "api_or_runner_failure")


def scope_filter(row: dict[str, Any], scope: str) -> bool:
    tier = row.get("confidence_level")
    if not tier:
        tier = "external_high_flow" if row["label_confidence"] == "high" and row["record_type"] == "flow_only" else "external_high_pcap" if row["label_confidence"] == "high" else "external_medium" if row["label_confidence"] == "medium" else "external_low"
    if scope == "strict external":
        return tier in {"external_high_pcap", "external_high_flow"}
    if scope in {"external_high_pcap", "external_high_flow", "external_medium", "external_low", "synthetic_controlled"}:
        return tier == scope
    if scope == "flow_only":
        return row["record_type"] == "flow_only"
    if scope == "pcap/session-derived":
        return row["record_type"] != "flow_only"
    return scope == "coverage all"


def metric_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for prompt_type in ("no_rag", "rag"):
        prompt_rows = [row for row in rows if row["prompt_type"] == prompt_type]
        for scope in EVAL_SCOPES:
            scoped = [row for row in prompt_rows if scope_filter(row, scope)]
            total = len(scoped)
            correct = sum(row["predicted_code"] == row["ground_truth_technique_code"] for row in scoped)
            parse_failures = sum(row["error_type"] == "json_parse_failure" for row in scoped)
            illegal = sum(row["error_type"] == "illegal_code" for row in scoped)
            output.append({
                "prompt_type": prompt_type, "scope": scope, "total": total, "correct": correct,
                "accuracy": correct / total if total else None,
                "json_parse_failure_rate": parse_failures / total if total else None,
                "illegal_code_rate": illegal / total if total else None,
            })
    return output


def fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare paired no-RAG and RAG technique predictions.")
    parser.add_argument("--eval-records", type=Path, default=ROOT / "datasets/public_eval/coverage_eval_records.jsonl")
    parser.add_argument("--context", type=Path, default=ROOT / "outputs/eval/rag_vs_no_rag/eval_context.json")
    parser.add_argument("--no-rag-dir", type=Path, default=ROOT / "outputs/eval/rag_vs_no_rag/api/no_rag")
    parser.add_argument("--rag-dir", type=Path, default=ROOT / "outputs/eval/rag_vs_no_rag/api/rag")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/eval/rag_vs_no_rag")
    args = parser.parse_args()
    records = load_jsonl(args.eval_records)
    context = load_json(args.context, {})
    selected_ids = context.get("selected_record_ids")
    if selected_ids:
        selected = set(selected_ids)
        records = [item for item in records if item.get("record_id") in selected]
    context_records = context.get("records", {})
    long_rows: list[dict[str, Any]] = []
    for prompt_type, result_dir in (("no_rag", args.no_rag_dir), ("rag", args.rag_dir)):
        result_map, status_map, raw_map = load_runner_rows(result_dir)
        for record in records:
            record_id = record["record_id"]
            parsed = result_map.get(record_id)
            status = status_map.get(record_id)
            if parsed:
                parse_status, error_type = "success", ""
            else:
                parse_status, error_type = failure_type(status)
            retrieval = context_records.get(record_id, {}).get("retrieved_docs", []) if prompt_type == "rag" else []
            long_rows.append({
                "record_id": record_id,
                "dataset_id": record["dataset_id"],
                "ground_truth_technique_code": record["technique_code"],
                "label_confidence": record["label_confidence"],
                "confidence_level": record.get("confidence_level"),
                "record_type": record["record_type"],
                "prompt_type": prompt_type,
                "prompt_version": context.get("prompt_version", "unknown"),
                "retrieved_docs": retrieval,
                "raw_output": raw_map.get(record_id, ""),
                "parsed_output": parsed,
                "predicted_code": parsed.get("predicted_code") if parsed else None,
                "confidence": parsed.get("confidence") if parsed else None,
                "parse_status": parse_status,
                "error_type": error_type,
            })
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "results_long.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in long_rows), encoding="utf-8")

    with (args.output_dir / "confusion_matrix.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["prompt_type", "actual_code", "predicted_code", "count"])
        writer.writeheader()
        confusion = Counter((row["prompt_type"], row["ground_truth_technique_code"], row["predicted_code"] or ERROR_CODE) for row in long_rows)
        for key, count in sorted(confusion.items()):
            writer.writerow({"prompt_type": key[0], "actual_code": key[1], "predicted_code": key[2], "count": count})

    with (args.output_dir / "per_class_metrics.csv").open("w", encoding="utf-8", newline="") as handle:
        fields = ["prompt_type", "scope", "technique_code", "total", "correct", "accuracy"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for prompt_type in ("no_rag", "rag"):
            for scope in EVAL_SCOPES:
                scoped = [row for row in long_rows if row["prompt_type"] == prompt_type and scope_filter(row, scope)]
                for code in TECHNIQUE_CODES:
                    code_rows = [row for row in scoped if row["ground_truth_technique_code"] == code]
                    if not code_rows:
                        continue
                    correct = sum(row["predicted_code"] == code for row in code_rows)
                    writer.writerow({"prompt_type": prompt_type, "scope": scope, "technique_code": code, "total": len(code_rows), "correct": correct, "accuracy": f"{correct / len(code_rows):.6f}"})

    paired: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in long_rows:
        paired[row["record_id"]][row["prompt_type"]] = row
    improved: list[str] = []
    worsened: list[str] = []
    disagreements: list[str] = []
    error_cases: list[dict[str, Any]] = []
    for record_id, pair in paired.items():
        no_rag, rag = pair.get("no_rag"), pair.get("rag")
        if not no_rag or not rag:
            continue
        truth = no_rag["ground_truth_technique_code"]
        no_correct = no_rag["predicted_code"] == truth
        rag_correct = rag["predicted_code"] == truth
        if not no_correct and rag_correct:
            improved.append(record_id)
        if no_correct and not rag_correct:
            worsened.append(record_id)
        if no_rag["predicted_code"] != rag["predicted_code"]:
            disagreements.append(record_id)
        if (not no_correct) or (not rag_correct) or no_rag["error_type"] or rag["error_type"] or record_id in disagreements:
            error_cases.append({
                "record_id": record_id, "dataset_id": no_rag["dataset_id"], "ground_truth": truth,
                "label_confidence": no_rag["label_confidence"], "record_type": no_rag["record_type"],
                "confidence_level": no_rag.get("confidence_level"),
                "no_rag_prediction": no_rag["predicted_code"], "rag_prediction": rag["predicted_code"],
                "no_rag_error": no_rag["error_type"], "rag_error": rag["error_type"],
                "rag_improved": record_id in improved, "rag_worsened": record_id in worsened,
            })
    (args.output_dir / "error_cases.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in error_cases), encoding="utf-8")

    metrics = metric_rows(long_rows)
    lines = [
        "# RAG vs no-RAG paired evaluation", "",
        f"- Records: {len(records)}", f"- Paired result rows: {len(long_rows)}",
        f"- Prompt version: `{context.get('prompt_version', 'unknown')}`",
        f"- Model: `{context.get('model', 'unknown')}`",
        f"- Endpoint host: `{context.get('base_url_host', 'unknown')}`",
        f"- RAG improved cases: {len(improved)}",
        f"- RAG worsened cases: {len(worsened)}",
        f"- RAG/no-RAG disagreements: {len(disagreements)}", "",
        "## Metrics by required scope", "",
        "| Prompt | Scope | N | Accuracy | JSON parse failure | Illegal code |",
        "|---|---|---:|---:|---:|---:|",
    ]
    if str(context.get("model", "")).lower().startswith("mock"):
        lines[11:11] = ["- Validation mode: local deterministic mock; accuracy below verifies plumbing only and is not a model-quality result.", ""]
    for metric in metrics:
        lines.append(f"| {metric['prompt_type']} | {metric['scope']} | {metric['total']} | {fmt_rate(metric['accuracy'])} | {fmt_rate(metric['json_parse_failure_rate'])} | {fmt_rate(metric['illegal_code_rate'])} |")
    important_pairs = [("TA43_01", "TA43_02"), ("TA01_01", "TN01_01"), ("TA01_02", "TN01_01"), ("TA11_02", "TN01_01"), ("TA11_01", "TA11_02")]
    lines.extend(["", "## Selected confusion pairs", "", "| Prompt | Pair | Count |", "|---|---|---:|"])
    for prompt_type in ("no_rag", "rag"):
        for left, right in important_pairs:
            count = confusion[(prompt_type, left, right)] + confusion[(prompt_type, right, left)]
            lines.append(f"| {prompt_type} | `{left}` ↔ `{right}` | {count} |")
    lines.extend(["", "## Pair changes", "", f"- Improved IDs: {', '.join(improved) if improved else 'none'}", f"- Worsened IDs: {', '.join(worsened) if worsened else 'none'}", f"- Disagreement IDs: {', '.join(disagreements) if disagreements else 'none'}", "", "Only external_high_pcap/external_high_flow rows enter strict external metrics. Medium/low and synthetic rows remain coverage-only."])
    (args.output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"records": len(records), "rows": len(long_rows), "improved": len(improved), "worsened": len(worsened), "disagreements": len(disagreements)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

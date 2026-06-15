#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from qwen35_rag_utils import ROOT


TECHNIQUE_CODES = ["TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"]
STAGE_CODES = ["TA43", "TA01", "TA03", "TA11", "TN01"]
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


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT))


def load_results(directory: Path) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    result_path = directory / "results.json"
    data = load_json(result_path, [])
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return by_id
    for item in data:
        if not isinstance(item, dict):
            continue
        rid = item.get("record_id") or item.get("session_id")
        if rid:
            copy = dict(item)
            copy["_source_file"] = rel(result_path)
            by_id[str(rid)] = copy
    return by_id


def load_stats(directory: Path) -> dict[str, Any]:
    return load_json(directory / "run_stats.json", {})


def timeout_count(stats: dict[str, Any]) -> int:
    rows = stats.get("rows") or []
    return sum(
        1
        for row in rows
        if "timeout" in str(row.get("error_category", "")).lower()
        or "timed out" in str(row.get("error", "")).lower()
    )


def status_count(stats: dict[str, Any], status: str) -> int:
    return sum(1 for row in stats.get("rows") or [] if row.get("status") == status)


def write_run_report(base: Path, name: str, directory: Path, selected_ids: list[str]) -> dict[str, Any]:
    stats = load_stats(directory)
    results = load_results(directory)
    result_ids = [rid for rid in selected_ids if rid in results]
    report = {
        "run_name": name,
        "output_dir": rel(directory),
        "status": "completed" if stats else "missing",
        "recovered_after_manual_termination": bool(stats.get("recovered_after_manual_termination")),
        "terminated_inflight_attempts": int(stats.get("terminated_inflight_attempts", 0) or 0),
        "termination_reason": stats.get("termination_reason") or "",
        "batches": int(stats.get("batches", 0) or 0),
        "success": int(stats.get("success", 0) or 0),
        "skipped_existing": int(stats.get("skipped_existing", 0) or 0),
        "failed": int(stats.get("failed", 0) or 0),
        "timeout": timeout_count(stats),
        "api_calls_attempted": int(stats.get("api_calls_attempted", 0) or 0),
        "records_in_results": len(result_ids),
        "json_parse_failures": int(stats.get("json_parse_failures", 0) or 0),
        "invalid_code_count": int(stats.get("invalid_code_count", 0) or 0),
        "error_counts": stats.get("error_counts") or {},
    }
    write_json(base / f"{name}_run_report.json", report)
    write_text(
        base / f"{name}_run_report.md",
        [
            f"# {name} run report",
            "",
            f"- Output dir: `{report['output_dir']}`",
            f"- Status: {report['status']}",
            f"- Recovered after manual termination: {str(report['recovered_after_manual_termination']).lower()}",
            f"- Terminated in-flight attempts: {report['terminated_inflight_attempts']}",
            f"- Batches: {report['batches']}",
            f"- Success / skipped / failed: {report['success']} / {report['skipped_existing']} / {report['failed']}",
            f"- Timeout: {report['timeout']}",
            f"- API calls attempted: {report['api_calls_attempted']}",
            f"- Records in results: {report['records_in_results']}",
            f"- JSON parse failures: {report['json_parse_failures']}",
            f"- Invalid code count: {report['invalid_code_count']}",
            f"- HTTP/API error counts: `{json.dumps(report['error_counts'], sort_keys=True)}`",
        ],
    )
    return report


def non_secret_env_value(name: str) -> str:
    if os.environ.get(name):
        return os.environ[name]
    env_path = ROOT / ".env"
    if not env_path.exists() or name in {"LLM_API_KEY", "HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN"}:
        return ""
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip().strip('"').strip("'")
    return ""


def safe_host() -> str:
    base_url = non_secret_env_value("LLM_BASE_URL")
    parsed = urlparse(base_url)
    return parsed.netloc or ("not_configured" if not base_url else base_url.split("/")[0])


def metric_rows(confusion: Counter[tuple[str, str]]) -> dict[str, dict[str, float | int]]:
    labels = sorted({label for pair in confusion for label in pair if label})
    out: dict[str, dict[str, float | int]] = {}
    for label in labels:
        tp = confusion.get((label, label), 0)
        fp = sum(count for (ref, pred), count in confusion.items() if pred == label and ref != label)
        fn = sum(count for (ref, pred), count in confusion.items() if ref == label and pred != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        out[label] = {"precision": precision, "recall": recall, "f1": f1, "support": tp + fn}
    return out


def distribution(results: dict[str, dict[str, Any]], selected_ids: list[str]) -> dict[str, int]:
    counts = {code: 0 for code in TECHNIQUE_CODES}
    for rid in selected_ids:
        code = results.get(rid, {}).get("predicted_code")
        if code in counts:
            counts[code] += 1
    return counts


def count_error(stats: dict[str, Any], code: str) -> int:
    return int((stats.get("error_counts") or {}).get(code, 0) or 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Write final medium-scale API reports from bounded technique RAG runs.")
    parser.add_argument("--base-dir", type=Path, default=ROOT / "outputs/api_tests/medium_scale")
    parser.add_argument("--smoke-dir", type=Path)
    parser.add_argument("--fifty-dir", type=Path)
    parser.add_argument("--scan-group-dir", type=Path)
    args = parser.parse_args()

    base = args.base_dir
    smoke_dir = args.smoke_dir or base / "results_technique_rag_smoke10"
    fifty_dir = args.fifty_dir or base / "results_technique_rag_50"
    scan_group_dir = args.scan_group_dir or base / "results_technique_rag_scan_group_final"

    selected = load_json(base / "selected_records.json", [])
    selected_ids = [str(record["record_id"]) for record in selected]
    selected_by_id = {str(record["record_id"]): record for record in selected}
    reference = load_json(base / "public_reference_labels.json", {})

    smoke_report = write_run_report(base, "smoke10", smoke_dir, selected_ids)
    fifty_report = write_run_report(base, "technique_rag_50", fifty_dir, selected_ids)
    scan_report = write_run_report(base, "technique_rag_scan_group_final", scan_group_dir, selected_ids)
    write_json(
        base / "technique_rag_96_run_report.json",
        {
            "status": "not_run",
            "reason": "Stopped after successful 50-record expansion plus targeted scan_group check to avoid HF Router latency/time-cost risk.",
            "max_allowed_calls": 96,
        },
    )
    write_text(
        base / "technique_rag_96_run_report.md",
        [
            "# technique_rag_96 run report",
            "",
            "- Status: not_run",
            "- Reason: stopped after successful 50-record expansion plus targeted scan_group check to avoid HF Router latency/time-cost risk.",
            "- Max allowed calls remained 96; no stage_rag calls were made.",
        ],
    )

    merged_results = load_results(fifty_dir)
    for rid, item in load_results(scan_group_dir).items():
        merged_results[rid] = item

    merged_selected = {rid: merged_results[rid] for rid in selected_ids if rid in merged_results}
    invalid_codes = [
        {"record_id": rid, "predicted_code": item.get("predicted_code")}
        for rid, item in merged_selected.items()
        if item.get("predicted_code") not in TECHNIQUE_CODES
    ]
    technique_dist = distribution(merged_selected, selected_ids)
    scan_group_code = merged_selected.get("feasibility_portscan::scan_group::000001", {}).get("predicted_code")
    scan_group_tested = "feasibility_portscan::scan_group::000001" in merged_selected

    merged_dir = base / "merged_results"
    write_json(merged_dir / "technique_rag_results.json", [merged_selected[rid] for rid in selected_ids if rid in merged_selected])

    smoke_stats = load_stats(smoke_dir)
    fifty_stats = load_stats(fifty_dir)
    scan_stats = load_stats(scan_group_dir)
    actual_api_calls = sum(
        int(stats.get("api_calls_attempted", 0) or 0)
        for stats in (smoke_stats, fifty_stats, scan_stats)
    )
    failed_api_batches = sum(int(stats.get("failed", 0) or 0) for stats in (smoke_stats, fifty_stats, scan_stats))
    terminated_inflight_attempts = sum(
        int(stats.get("terminated_inflight_attempts", 0) or 0)
        for stats in (smoke_stats, fifty_stats, scan_stats)
    )
    timeout_batches = sum(timeout_count(stats) for stats in (smoke_stats, fifty_stats, scan_stats)) + terminated_inflight_attempts
    json_parse_failures = sum(int(stats.get("json_parse_failures", 0) or 0) for stats in (smoke_stats, fifty_stats, scan_stats))
    error_counts = Counter()
    for stats in (smoke_stats, fifty_stats, scan_stats):
        error_counts.update(stats.get("error_counts") or {})
    auth_or_quota_errors = sum(count_error(stats, code) for stats in (smoke_stats, fifty_stats, scan_stats) for code in ("401", "402"))
    rate_limit_errors = sum(count_error(stats, "429") for stats in (smoke_stats, fifty_stats, scan_stats))

    merge_report = {
        "api_actually_run": actual_api_calls > 0,
        "actual_api_calls_attempted": actual_api_calls,
        "selected_records": len(selected_ids),
        "technique_results": len(merged_selected),
        "selected_missing": len(selected_ids) - len(merged_selected),
        "failed_api_batches": failed_api_batches,
        "timeout_or_terminated_long_tail_attempts": timeout_batches,
        "terminated_inflight_attempts": terminated_inflight_attempts,
        "json_parse_failures": json_parse_failures,
        "invalid_code_count": len(invalid_codes),
        "http_api_error_counts": dict(error_counts),
        "distribution": technique_dist,
        "portscan_scan_group_tested": scan_group_tested,
        "portscan_scan_group_code": scan_group_code,
        "portscan_scan_group_is_TA43_01": scan_group_code == "TA43_01",
    }
    write_json(merged_dir / "technique_rag_merge_report.json", merge_report)
    write_text(
        merged_dir / "technique_rag_merge_report.md",
        [
            "# Final technique RAG merge report",
            "",
            f"- API actually run: {str(merge_report['api_actually_run']).lower()}",
            f"- Actual API calls attempted: {actual_api_calls}",
            f"- Selected records: {len(selected_ids)}",
            f"- Technique results merged: {len(merged_selected)}",
            f"- Missing selected records: {merge_report['selected_missing']}",
            f"- Failed API batches: {failed_api_batches}",
            f"- Timeout or terminated long-tail attempts: {timeout_batches}",
            f"- Terminated in-flight attempts: {terminated_inflight_attempts}",
            f"- JSON parse failures: {json_parse_failures}",
            f"- Invalid code count: {len(invalid_codes)}",
            f"- HTTP/API error counts: `{json.dumps(dict(error_counts), sort_keys=True)}`",
            f"- Distribution: `{json.dumps(technique_dist, sort_keys=True)}`",
            f"- Portscan scan_group tested: {str(scan_group_tested).lower()}",
            f"- Portscan scan_group predicted `TA43_01`: {str(scan_group_code == 'TA43_01').lower()}",
        ],
    )

    stage_from_technique = []
    for rid in selected_ids:
        item = merged_selected.get(rid)
        code = item.get("predicted_code") if item else None
        if code in TECHNIQUE_TO_STAGE:
            record = selected_by_id[rid]
            stage_from_technique.append(
                {
                    "record_id": rid,
                    "pcap_id": record.get("pcap_id"),
                    "session_id": record.get("session_id") or rid,
                    "record_type": record.get("record_type"),
                    "predicted_code": TECHNIQUE_TO_STAGE[code],
                    "source_technique_code": code,
                    "source": "stage_from_technique",
                }
            )
    write_json(base / "stage_from_technique_results.json", stage_from_technique)
    write_text(
        base / "stage_from_technique_report.md",
        [
            "# Stage from technique fallback report",
            "",
            f"- Direct stage_rag run: false",
            f"- Technique results available for fallback: {len(stage_from_technique)}",
            f"- Fallback CSV rows available: {len(stage_from_technique)}",
            "- Mapping: `TA43_01`/`TA43_02` -> `TA43`; `TA01_01`/`TA01_02` -> `TA01`; `TA03_01` -> `TA03`; `TA11_01`/`TA11_02` -> `TA11`; `TN01_01` -> `TN01`.",
        ],
    )

    technique_rows = []
    stage_rows = []
    stage_by_id = {item["record_id"]: item for item in stage_from_technique}
    for rid in selected_ids:
        record = selected_by_id[rid]
        item = merged_selected.get(rid)
        technique_code = item.get("predicted_code") if item else None
        if technique_code in TECHNIQUE_CODES:
            technique_rows.append(
                {
                    "pcap_id": record.get("pcap_id"),
                    "session_id": record.get("session_id") or rid,
                    "technique_code": technique_code,
                }
            )
        stage_item = stage_by_id.get(rid)
        stage_code = stage_item.get("predicted_code") if stage_item else None
        if stage_code in STAGE_CODES:
            stage_rows.append(
                {
                    "pcap_id": record.get("pcap_id"),
                    "session_id": record.get("session_id") or rid,
                    "stage_code": stage_code,
                }
            )
    submissions = base / "submissions"
    write_csv(submissions / "stage2_submission_model_test.csv", ["pcap_id", "session_id", "technique_code"], technique_rows)
    write_csv(submissions / "stage1_submission_from_technique_fallback.csv", ["pcap_id", "session_id", "stage_code"], stage_rows)
    write_text(
        submissions / "submission_export_report.md",
        [
            "# Final medium-scale submission export report",
            "",
            f"- Selected records: {len(selected_ids)}",
            f"- Technique CSV: `{rel(submissions / 'stage2_submission_model_test.csv')}`",
            f"- Technique CSV rows exported: {len(technique_rows)}",
            f"- Stage fallback CSV: `{rel(submissions / 'stage1_submission_from_technique_fallback.csv')}`",
            f"- Stage fallback CSV rows exported: {len(stage_rows)}",
            f"- Missing selected records not exported: {len(selected_ids) - len(technique_rows)}",
            "- Missing predictions were not fabricated.",
            "- CSV encoding: utf-8-sig.",
        ],
    )

    reliable_qualities = {"high", "medium", "high_controlled"}
    eval_pairs: list[tuple[str, str]] = []
    unknown_or_unreliable = 0
    for rid, item in merged_selected.items():
        ref = reference.get(rid, {})
        ref_code = ref.get("reference_code")
        quality = ref.get("reference_quality")
        pred_code = item.get("predicted_code")
        if ref_code in TECHNIQUE_CODES and quality in reliable_qualities:
            eval_pairs.append((ref_code, pred_code))
        else:
            unknown_or_unreliable += 1
    confusion: Counter[tuple[str, str]] = Counter(eval_pairs)
    correct = sum(count for (ref, pred), count in confusion.items() if ref == pred)
    evaluated = sum(confusion.values())
    eval_json = {
        "not_official_competition_evaluation": True,
        "evaluated_records": evaluated,
        "unknown_or_unreliable_records_with_predictions": unknown_or_unreliable,
        "accuracy": correct / evaluated if evaluated else None,
        "correct": correct,
        "confusion_counts": {f"{ref}->{pred}": count for (ref, pred), count in confusion.items()},
        "per_class": metric_rows(confusion),
        "reference_distribution_all_selected": dict(Counter((reference.get(rid, {}) or {}).get("reference_code") or "unknown" for rid in selected_ids)),
        "note": "CTU normal-like heuristic records are intentionally excluded from accuracy because reliable From-Normal joins were unavailable.",
    }
    write_json(base / "public_label_eval_final.json", eval_json)
    write_text(
        base / "public_label_eval_final.md",
        [
            "# Final medium-scale public label evaluation",
            "",
            "- This is not an official competition evaluation.",
            "- Only reliable/high-confidence public feasibility references are evaluated.",
            f"- Evaluated prediction records: {evaluated}",
            f"- Correct: {correct}",
            f"- Accuracy: {eval_json['accuracy'] if eval_json['accuracy'] is not None else 'not meaningful'}",
            f"- Unknown or unreliable prediction records: {unknown_or_unreliable}",
            f"- Confusion counts: `{json.dumps(eval_json['confusion_counts'], sort_keys=True)}`",
            "- CTU normal-like heuristic records are excluded from accuracy because reliable `From-Normal*` joins were unavailable.",
        ],
    )

    ctu_botnet_preds = [
        item.get("predicted_code")
        for rid, item in merged_selected.items()
        if (reference.get(rid, {}) or {}).get("selection_role") == "ctu_botnet_like"
    ]
    ctu_normal_preds = [
        item.get("predicted_code")
        for rid, item in merged_selected.items()
        if (reference.get(rid, {}) or {}).get("selection_role") == "ctu_normal_like_heuristic"
    ]

    if not actual_api_calls:
        verdict = "NEEDS_FIX"
    elif auth_or_quota_errors:
        verdict = "MEDIUM_SCALE_BLOCKED_BY_API_QUOTA_OR_AUTH"
    elif timeout_batches:
        verdict = "MEDIUM_SCALE_NEEDS_TIMEOUT_FIX"
    elif len(merged_selected) >= len(selected_ids) and not invalid_codes:
        verdict = "MEDIUM_SCALE_TECHNIQUE_RAG_PASSED"
    elif len(merged_selected) >= 50 and not invalid_codes and failed_api_batches == 0:
        verdict = "MEDIUM_SCALE_PARTIAL_SUCCESS_USABLE"
    else:
        verdict = "NEEDS_FIX"

    host = safe_host()
    endpoint_kind = "HF Router" if host == "router.huggingface.co" else ("not configured" if host == "not_configured" else "local/other endpoint")
    final_summary_lines = [
        "# Final medium-scale Qwen3.5 technique RAG API summary",
        "",
        f"- API actually run: {str(actual_api_calls > 0).lower()}",
        f"- Endpoint kind: {endpoint_kind}",
        f"- Base URL host: `{host}`",
        f"- Model name: `{non_secret_env_value('LLM_MODEL_NAME') or 'not_configured'}`",
        f"- Selected records: {len(selected_ids)}",
        f"- Final tested records with technique predictions: {len(merged_selected)}",
        f"- Technique success/failure/timeout: {len(merged_selected)}/{failed_api_batches}/{timeout_batches}",
        f"- Technique selected missing after bounded run: {len(selected_ids) - len(merged_selected)}",
        f"- API calls attempted: {actual_api_calls}",
        f"- JSON parse failures: {json_parse_failures}",
        f"- Invalid technique code count: {len(invalid_codes)}",
        f"- 401/402/429 counts: {sum(count_error(stats, '401') for stats in (smoke_stats, fifty_stats, scan_stats))}/{sum(count_error(stats, '402') for stats in (smoke_stats, fifty_stats, scan_stats))}/{rate_limit_errors}",
        f"- Stage_from_technique fallback used for CSV: {str(bool(stage_rows)).lower()}",
        f"- Stage fallback rows: {len(stage_rows)}",
        f"- CSV exported: {str(bool(technique_rows and stage_rows)).lower()}",
        f"- Portscan scan_group tested: {str(scan_group_tested).lower()}",
        f"- Portscan scan_group predicted `TA43_01`: {str(scan_group_code == 'TA43_01').lower()}",
        f"- Public label rough eval records/correct/accuracy: {evaluated}/{correct}/{eval_json['accuracy'] if eval_json['accuracy'] is not None else 'not meaningful'}",
        f"- CTU botnet-like tendency toward `TA11_02`: {ctu_botnet_preds.count('TA11_02')}/{len(ctu_botnet_preds)} predictions",
        f"- CTU normal-like tendency toward `TN01_01`: {ctu_normal_preds.count('TN01_01')}/{len(ctu_normal_preds)} predictions",
        "- Direct stage_rag run: false",
        "- Expand to 96: false; stopped after recovered 50-run reached a stable partial result plus targeted scan_group because HF Router long-tail latency made full 96 unsafe for this bounded run.",
        "- Raw and parsed model outputs remain in ignored output directories.",
        f"- Verdict: `{verdict}`",
    ]
    write_text(ROOT / "docs/medium_scale_qwen35_rag_final_api_summary.md", final_summary_lines)
    write_text(
        ROOT / "docs/git_commit_summary_medium_scale_final_api.md",
        [
            "# Git commit summary: final medium-scale API evaluation",
            "",
            "## Included",
            "",
            "- Final medium-scale API readiness note.",
            "- Final API run reports for smoke10, 50-record expansion, targeted scan_group, and skipped 96-record expansion decision.",
            "- Merge, fallback, submission-export, and public-label evaluation reports.",
            "- Final summary document with non-secret endpoint metadata and verdict.",
            "",
            "## Excluded",
            "",
            "- `.env` and token values.",
            "- Raw API responses and parsed per-batch model outputs.",
            "- Prompt directories and large/generated CSV outputs.",
            "- PCAP/raw public datasets, model weights, and adapters.",
        ],
    )

    print(
        json.dumps(
            {
                "api_actually_run": actual_api_calls > 0,
                "tested_records": len(merged_selected),
                "technique_success": len(merged_selected),
                "technique_failed": failed_api_batches,
                "technique_timeout": timeout_batches,
                "portscan_scan_group_is_TA43_01": scan_group_code == "TA43_01",
                "csv_exported": bool(technique_rows and stage_rows),
                "public_eval_accuracy": eval_json["accuracy"],
                "verdict": verdict,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

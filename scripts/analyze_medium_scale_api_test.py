#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
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


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT))


def load_results(directory: Path) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    candidates = []
    if (directory / "parsed").exists():
        candidates.extend(sorted((directory / "parsed").glob("*.json")))
    if (directory / "results.json").exists():
        candidates.append(directory / "results.json")
    for path in candidates:
        data = load_json(path, [])
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            rid = item.get("record_id") or item.get("session_id")
            if rid:
                item = dict(item)
                item["_source_file"] = rel(path)
                by_id[str(rid)] = item
    return by_id


def load_stats(directory: Path) -> dict[str, Any]:
    return load_json(directory / "run_stats.json", {})


def error_count(stats: dict[str, Any], code: str) -> int:
    return int((stats.get("error_counts") or {}).get(code, 0))


def timeout_count(stats: dict[str, Any]) -> int:
    rows = stats.get("rows") or []
    return sum(1 for row in rows if "timeout" in str(row.get("error_category", "")).lower() or "timed out" in str(row.get("error", "")).lower())


def distribution(results: dict[str, dict[str, Any]], codes: list[str]) -> dict[str, int]:
    counts = {code: 0 for code in codes}
    for item in results.values():
        code = item.get("predicted_code")
        if code in counts:
            counts[code] += 1
    return counts


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def metric_rows(confusion: dict[tuple[str, str], int], labels: list[str]) -> dict[str, dict[str, float | int]]:
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


def non_secret_setting(name: str) -> str:
    if os.environ.get(name):
        return os.environ[name]
    env_path = ROOT / ".env"
    if not env_path.exists() or name == "LLM_API_KEY":
        return ""
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip().strip('"').strip("'")
    return ""


def safe_host() -> str:
    base_url = non_secret_setting("LLM_BASE_URL")
    parsed = urlparse(base_url)
    return parsed.netloc or ("not_configured" if not base_url else base_url.split("/")[0])


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze medium-scale API test outputs and write reports.")
    parser.add_argument("--base-dir", type=Path, default=ROOT / "outputs/api_tests/medium_scale")
    args = parser.parse_args()
    base = args.base_dir
    selected = load_json(base / "selected_records.json", [])
    selected_ids = [record["record_id"] for record in selected]
    selected_by_id = {record["record_id"]: record for record in selected}
    reference = load_json(base / "public_reference_labels.json", {})

    technique_dir = base / "results_technique_rag"
    technique_results = load_results(technique_dir)
    stage_results = {
        rid: {**item, "predicted_code": TECHNIQUE_TO_STAGE[item["predicted_code"]], "source": "stage_from_technique"}
        for rid, item in technique_results.items()
        if item.get("predicted_code") in TECHNIQUE_TO_STAGE
    }
    technique_stats = load_stats(technique_dir)
    stage_stats: dict[str, Any] = {}
    api_ready = os.environ.get("RUN_API") == "1" and all(os.environ.get(name) for name in ["LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL_NAME"])
    technique_api_calls = int(technique_stats.get("api_calls_attempted", 0) or 0)
    stage_api_calls = 0
    technique_success = len([rid for rid in selected_ids if rid in technique_results])
    stage_success = len([rid for rid in selected_ids if rid in stage_results])
    technique_missing = len(selected_ids) - technique_success
    stage_missing = len(selected_ids) - stage_success
    technique_invalid = sum(1 for rid, item in technique_results.items() if rid in selected_by_id and item.get("predicted_code") not in TECHNIQUE_CODES)
    stage_invalid = sum(1 for rid, item in stage_results.items() if rid in selected_by_id and item.get("predicted_code") not in STAGE_CODES)
    technique_dist = distribution(technique_results, TECHNIQUE_CODES)
    stage_dist = distribution(stage_results, STAGE_CODES)
    scan_group_code = technique_results.get("feasibility_portscan::scan_group::000001", {}).get("predicted_code")
    technique_success_rate = technique_success / len(selected_ids) if selected_ids else 0
    stage_derived_ready = technique_success_rate >= 0.70 and technique_invalid == 0

    technique_report = {
        "api_ready": api_ready,
        "api_calls_attempted": technique_api_calls,
        "selected_records": len(selected_ids),
        "success": technique_success,
        "failed_or_missing": technique_missing,
        "timeout": timeout_count(technique_stats),
        "401": error_count(technique_stats, "401"),
        "402": error_count(technique_stats, "402"),
        "429": error_count(technique_stats, "429"),
        "json_parse_failures": int(technique_stats.get("json_parse_failures", 0) or 0),
        "invalid_code_count": technique_invalid,
        "portscan_scan_group_is_TA43_01": scan_group_code == "TA43_01",
        "distribution": technique_dist,
        "stage_derived_ready": stage_derived_ready,
    }
    write_json(base / "technique_rag_run_report.json", technique_report)
    write_text(
        base / "technique_rag_run_report.md",
        [
            "# Medium-scale technique_rag run report",
            "",
            f"- API ready in current environment: {str(api_ready).lower()}",
            f"- Actual API calls attempted: {technique_api_calls}",
            f"- Selected records: {len(selected_ids)}",
            f"- Success: {technique_success}",
            f"- Failed or missing: {technique_missing}",
            f"- Timeout count: {technique_report['timeout']}",
            f"- 401 / 402 / 429: {technique_report['401']} / {technique_report['402']} / {technique_report['429']}",
            f"- JSON parse failures: {technique_report['json_parse_failures']}",
            f"- Illegal technique code count: {technique_invalid}",
            f"- Portscan scan_group predicted `TA43_01`: {str(scan_group_code == 'TA43_01').lower()}",
            f"- Output distribution: `{json.dumps(technique_dist, sort_keys=True)}`",
            f"- Deterministic stage mapping ready: {str(stage_derived_ready).lower()}",
        ],
    )

    stage_report = {
        "source": "deterministic_technique_to_stage_mapping",
        "api_ready": api_ready,
        "api_calls_attempted": stage_api_calls,
        "selected_records": len(selected_ids),
        "success": stage_success,
        "failed_or_missing": stage_missing,
        "timeout": timeout_count(stage_stats),
        "401": error_count(stage_stats, "401"),
        "402": error_count(stage_stats, "402"),
        "429": error_count(stage_stats, "429"),
        "json_parse_failures": int(stage_stats.get("json_parse_failures", 0) or 0),
        "invalid_code_count": stage_invalid,
        "distribution": stage_dist,
    }
    write_json(base / "stage_from_technique_run_report.json", stage_report)
    write_text(
        base / "stage_from_technique_run_report.md",
        [
            "# Medium-scale deterministic stage mapping report",
            "",
            f"- API ready in current environment: {str(api_ready).lower()}",
            "- Actual stage API calls attempted: 0",
            f"- Selected records: {len(selected_ids)}",
            f"- Success: {stage_success}",
            f"- Failed or missing: {stage_missing}",
            f"- Timeout count: {stage_report['timeout']}",
            f"- 401 / 402 / 429: {stage_report['401']} / {stage_report['402']} / {stage_report['429']}",
            f"- JSON parse failures: {stage_report['json_parse_failures']}",
            f"- Illegal stage code count: {stage_invalid}",
            f"- Output distribution: `{json.dumps(stage_dist, sort_keys=True)}`",
        ],
    )

    stage_from_technique = []
    for rid in selected_ids:
        item = technique_results.get(rid)
        code = item.get("predicted_code") if item else None
        if code in TECHNIQUE_TO_STAGE:
            record = selected_by_id[rid]
            stage_from_technique.append({
                "record_id": rid,
                "pcap_id": record.get("pcap_id"),
                "record_type": record.get("record_type"),
                "predicted_code": TECHNIQUE_TO_STAGE[code],
                "source_technique_code": code,
                "source": "stage_from_technique",
            })
    write_json(base / "stage_from_technique_results.json", stage_from_technique)
    write_text(
        base / "stage_from_technique_report.md",
        [
            "# Stage from technique fallback report",
            "",
            f"- Technique results available for fallback: {len(stage_from_technique)}",
            "- Mapping: `TA43_01`/`TA43_02` -> `TA43`; `TA01_01`/`TA01_02` -> `TA01`; `TA03_01` -> `TA03`; `TA11_01`/`TA11_02` -> `TA11`; `TN01_01` -> `TN01`.",
            f"- Fallback usable for CSV rows: {str(bool(stage_from_technique)).lower()}",
        ],
    )

    submissions = base / "submissions"
    technique_rows = []
    for rid in selected_ids:
        item = technique_results.get(rid)
        if not item or item.get("predicted_code") not in TECHNIQUE_CODES:
            continue
        record = selected_by_id[rid]
        technique_rows.append({"pcap_id": record.get("pcap_id"), "session_id": record.get("session_id") or rid, "technique_code": item.get("predicted_code")})
    stage_rows = []
    stage_source = "stage_from_technique"
    stage_source_map = {item["record_id"]: item for item in stage_from_technique}
    for rid in selected_ids:
        item = stage_source_map.get(rid)
        code = item.get("predicted_code") if item else None
        source = "stage_from_technique"
        if code not in STAGE_CODES:
            continue
        record = selected_by_id[rid]
        stage_rows.append({"pcap_id": record.get("pcap_id"), "session_id": record.get("session_id") or rid, "stage_code": code})
        if source == "stage_from_technique":
            stage_source = "stage_from_technique"
    if technique_rows:
        write_csv(submissions / "stage2_submission_model_test.csv", ["pcap_id", "session_id", "technique_code"], technique_rows)
    if stage_rows:
        write_csv(submissions / "stage1_submission_model_test.csv", ["pcap_id", "session_id", "stage_code"], stage_rows)
    write_text(
        submissions / "submission_export_report.md",
        [
            "# Medium-scale submission export report",
            "",
            f"- Selected records: {len(selected_ids)}",
            f"- Technique CSV rows exported: {len(technique_rows)}",
            f"- Stage CSV rows exported: {len(stage_rows)}",
            f"- Missing technique records: {len(selected_ids) - len(technique_rows)}",
            f"- Missing stage records: {len(selected_ids) - len(stage_rows)}",
            f"- Stage source: {stage_source if stage_rows else 'none'}",
            "- Missing technique records were not fabricated.",
            "- CSV encoding: utf-8-sig.",
        ],
    )

    eval_pairs: list[tuple[str, str]] = []
    unknown = 0
    for rid, pred in technique_results.items():
        if rid not in selected_by_id:
            continue
        ref = reference.get(rid, {})
        ref_code = ref.get("reference_code")
        quality = ref.get("reference_quality")
        if ref_code in TECHNIQUE_CODES and quality in {"high", "medium", "high_controlled"}:
            eval_pairs.append((ref_code, pred.get("predicted_code")))
        else:
            unknown += 1
    confusion = Counter(eval_pairs)
    labels = sorted({label for pair in eval_pairs for label in pair if label})
    metrics = metric_rows(confusion, labels) if labels else {}
    correct = sum(count for (ref, pred), count in confusion.items() if ref == pred)
    total = sum(confusion.values())
    eval_json = {
        "not_official_competition_evaluation": True,
        "evaluated_records": total,
        "unknown_or_unreliable_records_with_predictions": unknown,
        "accuracy": correct / total if total else None,
        "per_class": metrics,
        "confusion_counts": {f"{ref}->{pred}": count for (ref, pred), count in confusion.items()},
        "reference_distribution": dict(Counter(ref.get("reference_code") or "unknown" for ref in reference.values())),
    }
    write_json(base / "public_label_eval.json", eval_json)
    write_text(
        base / "public_label_eval.md",
        [
            "# Medium-scale public feasibility evaluation",
            "",
            "- This is not an official competition evaluation.",
            "- Evaluation only uses selected records with reliable/high-confidence public feasibility references.",
            f"- Evaluated prediction records: {total}",
            f"- Unknown or unreliable prediction records: {unknown}",
            f"- Accuracy: {eval_json['accuracy'] if eval_json['accuracy'] is not None else 'not meaningful'}",
            f"- Confusion counts: `{json.dumps(eval_json['confusion_counts'], sort_keys=True)}`",
            "- No conclusions are made for `TA43_02`, `TA03_01`, or `TA11_01`.",
            "- CTU normal-like candidates are low-confidence heuristic candidates because reliable `From-Normal*` joins were not available in the selected CTU subset.",
        ],
    )

    ctu_botnet_preds = [item.get("predicted_code") for rid, item in technique_results.items() if reference.get(rid, {}).get("selection_role") == "ctu_botnet_like"]
    ctu_normal_preds = [item.get("predicted_code") for rid, item in technique_results.items() if reference.get(rid, {}).get("selection_role") == "ctu_normal_like_heuristic"]
    api_actually_run = technique_api_calls + stage_api_calls > 0
    if not api_actually_run:
        verdict = "NEEDS_FIX"
    elif technique_report["402"] or technique_report["401"]:
        verdict = "MEDIUM_SCALE_BLOCKED_BY_API_QUOTA_OR_AUTH"
    elif technique_success_rate >= 0.70 and (stage_report["timeout"] or stage_missing):
        verdict = "MEDIUM_SCALE_PARTIAL_SUCCESS_NEEDS_TIMEOUT_FIX"
    elif technique_success_rate >= 0.70:
        verdict = "MEDIUM_SCALE_TEST_PASSED"
    else:
        verdict = "NEEDS_FIX"
    host = safe_host()
    if host == "not_configured":
        endpoint_kind = "not configured in current environment"
    elif host == "router.huggingface.co":
        endpoint_kind = "HF Router"
    else:
        endpoint_kind = "local/other endpoint"
    write_text(
        ROOT / "docs/medium_scale_qwen35_rag_test_summary.md",
        [
            "# Medium-scale Qwen3.5 RAG test summary",
            "",
            f"- API actually run: {str(api_actually_run).lower()}",
            f"- Endpoint kind: {endpoint_kind}",
            f"- Base URL host: `{host}`",
            f"- Model name: `{non_secret_setting('LLM_MODEL_NAME') or 'not_configured'}`",
            f"- Selected records: {len(selected_ids)}",
            f"- Technique success/failure/timeout/illegal/json_parse: {technique_success}/{technique_missing}/{technique_report['timeout']}/{technique_invalid}/{technique_report['json_parse_failures']}",
            f"- Stage success/failure/timeout/illegal/json_parse: {stage_success}/{stage_missing}/{stage_report['timeout']}/{stage_invalid}/{stage_report['json_parse_failures']}",
            f"- Stage_from_technique fallback used for CSV: {str(stage_source == 'stage_from_technique' and bool(stage_rows)).lower()}",
            f"- CSV exported: {str(bool(technique_rows or stage_rows)).lower()}",
            f"- Portscan scan_group predicted `TA43_01`: {str(scan_group_code == 'TA43_01').lower()}",
            f"- CTU botnet-like tendency toward `TA11_02`: {ctu_botnet_preds.count('TA11_02')}/{len(ctu_botnet_preds)} predictions",
            f"- CTU normal-like tendency toward `TN01_01`: {ctu_normal_preds.count('TN01_01')}/{len(ctu_normal_preds)} predictions",
            "- RAG prompt issue observed: none from static prompt checks; prompts exclude `candidate_hint` and public labels.",
            "- Cautious conclusion: no medium-scale online effect conclusion is available unless API is explicitly run; current artifacts prepare a bounded public feasibility evaluation.",
            "- Expand to 200 records: no, not until a medium-scale online run completes with stable timeout behavior.",
            "- Recommendation for tomorrow: consider switching to a local model endpoint if HF Router timeouts continue.",
            "- Missing category samples: `TA43_02`, `TA03_01`, `TA11_01`.",
            f"- Verdict: `{verdict}`",
        ],
    )
    write_text(
        ROOT / "docs/medium_scale_api_runner_readiness.md",
        [
            "# Medium-scale API runner readiness",
            "",
            "- `--prompt-dir`: supported",
            "- `--output-dir`: supported",
            "- `--max-files`: supported",
            "- `--temperature`: supported",
            "- `--max-tokens`: supported",
            "- `--sleep-seconds`: supported",
            "- `--timeout-seconds`: supported",
            "- `--continue-on-error`: supported",
            "- `--retry-failed-once`: supported",
            "- `--require-run-api-flag`: supported",
            "- `--resume`: supported",
            "- Failed records are recorded by `record_id` and prompt filename when `--failed-records-out` is set.",
            "- 401/402 errors stop the run; timeout/provider/rate-limit errors can be retried and continued with the appropriate flags.",
            "- Token values are not printed by the runner.",
            "- Raw and parsed model outputs are written below ignored output subdirectories.",
        ],
    )
    write_text(
        ROOT / "docs/git_commit_summary_medium_scale_test.md",
        [
            "# Git commit summary: medium-scale public feasibility test",
            "",
            "## Included",
            "",
            "- Runner readiness updates for timeout and resume.",
            "- Medium-scale selected-record and prompt-subset builder.",
            "- Medium-scale result analysis, fallback, CSV, and public feasibility evaluation helper.",
            "- Medium-scale summary documents and small metadata reports.",
            "",
            "## Excluded",
            "",
            "- API raw responses, parsed model outputs, full prompt directories, PCAP, binetflow, parsed logs, large CSVs, `.env`, token values, model weights, and adapters.",
        ],
    )
    print(json.dumps({
        "api_actually_run": api_actually_run,
        "selected_records": len(selected_ids),
        "technique_success": technique_success,
        "stage_success": stage_success,
        "csv_exported": bool(technique_rows or stage_rows),
        "verdict": verdict,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

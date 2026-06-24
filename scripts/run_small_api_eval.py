#!/usr/bin/env python3
"""Run guarded smoke and strict paired online evaluation for observable_boundary_rag_v3."""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from build_qwen35_session_prompts import PROMPT_VERSION
from qwen35_rag_utils import DEFAULT_RUNTIME_PROFILES, ROOT, load_env_file, load_runtime_profile
from run_public_eval_api import api_env, host_only, load_jsonl, write_prompts


TECHNIQUE_CODES = ["TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"]
TECHNIQUE_TO_STAGE = {
    "TA43_01": "TA43", "TA43_02": "TA43", "TA01_01": "TA01", "TA01_02": "TA01",
    "TA03_01": "TA03", "TA11_01": "TA11", "TA11_02": "TA11", "TN01_01": "TN01",
}
STRICT_TIERS = {"external_high_pcap", "external_high_flow"}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def select_records(rows: list[dict[str, Any]], subset: str, limit: int, limit_per_class: int) -> list[dict[str, Any]]:
    if subset == "strict":
        rows = [row for row in rows if "strict_subset" in row.get("subset_membership", []) and row.get("confidence_level") in STRICT_TIERS]
    elif subset == "coverage":
        rows = [row for row in rows if "coverage_subset" in row.get("subset_membership", [])]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row["technique_code"])].append(row)
    selected: list[dict[str, Any]] = []
    for index in range(limit_per_class):
        for code in TECHNIQUE_CODES:
            if index < len(groups.get(code, [])) and len(selected) < limit:
                selected.append(groups[code][index])
    return selected


def manifest_rows(phase_dir: Path, mode: str) -> list[dict[str, Any]]:
    path = phase_dir / "prompts" / mode / "prompt_manifest.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def estimate_phase_cost(
    phase_dir: Path, modes: list[str], expected_output_tokens: int,
    input_price: float, output_price: float,
) -> dict[str, Any]:
    manifests = [item for mode in modes for item in manifest_rows(phase_dir, mode)]
    input_tokens = sum(int(item.get("estimated_prompt_tokens") or 0) for item in manifests)
    output_tokens = len(manifests) * expected_output_tokens
    return {
        "calls": len(manifests),
        "estimated_input_tokens": input_tokens,
        "expected_output_tokens": output_tokens,
        "estimated_usd": round(input_tokens * input_price / 1_000_000 + output_tokens * output_price / 1_000_000, 6),
    }


def safety_check(
    phase: str, records: list[dict[str, Any]], base_url: str | None, model: str | None,
    api_key: str | None, estimate: dict[str, Any], run_api: bool,
) -> dict[str, Any]:
    check = {
        "phase": phase,
        "api_key_present": bool(api_key),
        "api_key_length": len(api_key) if api_key else 0,
        "api_key_value_printed": False,
        "base_url": base_url,
        "model": model,
        "record_count": len(records),
        **estimate,
        "RUN_REAL_API_TEST": os.environ.get("RUN_REAL_API_TEST") == "1",
        "run_api_requested": run_api,
    }
    print(json.dumps({"safe_preflight": check}, ensure_ascii=False))
    return check


def run_mode(mode: str, phase_dir: Path, args: argparse.Namespace) -> int:
    cmd = [
        sys.executable, str(ROOT / "scripts/run_qwen_openai_compatible.py"),
        "--prompt-dir", str(phase_dir / "prompts" / mode),
        "--output-dir", str(phase_dir / "api" / mode),
        "--result-name", "results.json", "--summary-name", "run_summary.md",
        "--temperature", str(args.temperature), "--max-tokens", str(args.max_output_tokens),
        "--timeout-seconds", str(args.timeout), "--retries", str(args.retries),
        "--continue-on-error", "--require-run-api-flag", "--enable-thinking", "false",
        "--runtime-profile", args.runtime_profile, "--runtime-profiles", str(args.runtime_profiles),
    ]
    if args.disable_extra_body:
        cmd.append("--disable-extra-body")
    if args.resume:
        cmd.append("--resume")
    env = os.environ.copy()
    env["RUN_API"] = "1"
    env["LLM_SEND_EXTRA_BODY"] = "false" if args.disable_extra_body else "true"
    return subprocess.run(cmd, cwd=ROOT, env=env, check=False).returncode


def load_result_map(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {row["record_id"]: row for row in data if isinstance(row, dict) and row.get("record_id")}


def load_status_map(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {row["record_id"]: row for row in data.get("rows", []) if row.get("record_id")}


def phase_rows(phase_dir: Path, records: list[dict[str, Any]], modes: list[str]) -> list[dict[str, Any]]:
    manifests = {mode: {row["record_id"]: row for row in manifest_rows(phase_dir, mode)} for mode in modes}
    output: list[dict[str, Any]] = []
    responses_dir = phase_dir / "responses"
    responses_dir.mkdir(parents=True, exist_ok=True)
    for mode in modes:
        result_map = load_result_map(phase_dir / "api" / mode / "results.json")
        status_map = load_status_map(phase_dir / "api" / mode / "run_stats.json")
        for record in records:
            record_id = record["record_id"]
            parsed = result_map.get(record_id)
            status = status_map.get(record_id, {})
            predicted = parsed.get("predicted_code") if parsed else None
            truth = record["technique_code"]
            usage = status.get("usage") or {}
            row = {
                "record_id": record_id,
                "mode": mode,
                "prompt_version": status.get("prompt_version", PROMPT_VERSION),
                "prompt_path": manifests[mode].get(record_id, {}).get("prompt_file"),
                "confidence_level": record.get("confidence_level"),
                "record_type": record.get("record_type"),
                "ground_truth_technique_code": truth,
                "ground_truth_stage_code": TECHNIQUE_TO_STAGE[truth],
                "predicted_technique_code": predicted,
                "predicted_stage_code": TECHNIQUE_TO_STAGE.get(predicted),
                "technique_correct": predicted == truth,
                "stage_correct": TECHNIQUE_TO_STAGE.get(predicted) == TECHNIQUE_TO_STAGE[truth],
                "api_success": status.get("status") in {"success", "skipped_existing"} and parsed is not None,
                "json_parse_success": bool(status.get("parse_success", parsed is not None)),
                "valid_label": bool(status.get("valid_label", predicted in TECHNIQUE_TO_STAGE)),
                "confidence": parsed.get("confidence") if parsed else None,
                "reason": parsed.get("reason") if parsed else None,
                "request_id": status.get("request_id"),
                "response_id": status.get("response_id"),
                "latency_seconds": status.get("latency_seconds"),
                "usage": usage,
                "error": status.get("error") or None,
                "error_category": status.get("error_category") or None,
                "retrieved_rag_chunks": manifests[mode].get(record_id, {}).get("rag_chunks_included", 0),
                "targeted_rag_triggers": manifests[mode].get(record_id, {}).get("targeted_rag_triggers", []),
                "targeted_boundary_cards": manifests[mode].get(record_id, {}).get("targeted_boundary_cards", []),
                "indicator_fields_used": manifests[mode].get(record_id, {}).get("indicator_fields_used", []),
                "observable_fields_included": manifests[mode].get(record_id, {}).get("observable_fields_included", []),
                "prompt_budget_summary": manifests[mode].get(record_id, {}).get("prompt_budget_summary", {}),
            }
            output.append(row)
            write_json(responses_dir / f"{mode}__{record_id}.json", {
                key: row[key] for key in (
                    "record_id", "mode", "prompt_version", "api_success", "json_parse_success", "valid_label",
                    "request_id", "response_id", "latency_seconds", "usage", "error", "error_category",
                )
            } | {"parsed_prediction": parsed})
    return output


def metric(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    return {
        "calls": total,
        "api_success": sum(row["api_success"] for row in rows),
        "api_success_rate": sum(row["api_success"] for row in rows) / total if total else None,
        "json_parse_success_rate": sum(row["json_parse_success"] for row in rows) / total if total else None,
        "valid_label_rate": sum(row["valid_label"] for row in rows) / total if total else None,
        "technique_accuracy": sum(row["technique_correct"] for row in rows) / total if total else None,
        "stage_accuracy": sum(row["stage_correct"] for row in rows) / total if total else None,
    }


def fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def summarize_phase(
    phase: str, phase_dir: Path, records: list[dict[str, Any]], modes: list[str],
    preflight: dict[str, Any], args: argparse.Namespace,
) -> dict[str, Any]:
    rows = phase_rows(phase_dir, records, modes) if args.run_api else []
    write_jsonl(phase_dir / "parsed_predictions.jsonl", rows)
    errors = [row for row in rows if not row["api_success"] or not row["json_parse_success"] or not row["valid_label"]]
    write_jsonl(phase_dir / "errors.jsonl", errors)
    paired: list[dict[str, Any]] = []
    by_record: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        by_record[row["record_id"]][row["mode"]] = row
    helpful = harmful = disagreements = 0
    for record in records:
        pair = by_record.get(record["record_id"], {})
        no_rag, rag = pair.get("no_rag"), pair.get("rag")
        effect = "unpaired"
        if no_rag and rag:
            if not no_rag["technique_correct"] and rag["technique_correct"]:
                effect, helpful = "helpful", helpful + 1
            elif no_rag["technique_correct"] and not rag["technique_correct"]:
                effect, harmful = "harmful", harmful + 1
            else:
                effect = "tie"
            disagreements += no_rag["predicted_technique_code"] != rag["predicted_technique_code"]
        paired.append({
            "record_id": record["record_id"], "confidence_level": record.get("confidence_level"),
            "record_type": record.get("record_type"), "ground_truth": record["technique_code"],
            "no_rag_prediction": no_rag and no_rag["predicted_technique_code"],
            "rag_prediction": rag and rag["predicted_technique_code"],
            "no_rag_correct": bool(no_rag and no_rag["technique_correct"]),
            "rag_correct": bool(rag and rag["technique_correct"]), "rag_effect": effect,
        })
    with (phase_dir / "paired_results.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(paired[0]) if paired else ["record_id"])
        writer.writeheader()
        writer.writerows(paired)
    confusion = Counter((row["mode"], row["ground_truth_technique_code"], row["predicted_technique_code"] or "__ERROR__") for row in rows)
    with (phase_dir / "confusion_matrix.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["mode", "actual_code", "predicted_code", "count"])
        for key, count in sorted(confusion.items()):
            writer.writerow([*key, count])
    metrics = {mode: metric([row for row in rows if row["mode"] == mode]) for mode in modes}
    tiers = sorted({str(record.get("confidence_level")) for record in records})
    tier_metrics = {
        tier: {mode: metric([row for row in rows if row["mode"] == mode and row["confidence_level"] == tier]) for mode in modes}
        for tier in tiers
    }
    per_class = {
        code: {mode: metric([row for row in rows if row["mode"] == mode and row["ground_truth_technique_code"] == code]) for mode in modes}
        for code in TECHNIQUE_CODES if any(row["ground_truth_technique_code"] == code for row in rows)
    }
    usage_input = sum(int((row.get("usage") or {}).get("prompt_tokens") or 0) for row in rows)
    usage_output = sum(int((row.get("usage") or {}).get("completion_tokens") or 0) for row in rows)
    latencies = [float(row["latency_seconds"]) for row in rows if row.get("latency_seconds") is not None]
    cost = {
        **preflight,
        "actual_input_tokens": usage_input,
        "actual_output_tokens": usage_output,
        "actual_usd": round(usage_input * args.input_price_per_million / 1_000_000 + usage_output * args.output_price_per_million / 1_000_000, 6),
        "latency_seconds_total": round(sum(latencies), 3),
        "latency_seconds_mean": round(statistics.mean(latencies), 3) if latencies else None,
        "latency_seconds_p95_observed": round(sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)], 3) if latencies else None,
    }
    write_json(phase_dir / "cost_summary.json", cost)
    engineering_gate = bool(rows) and all(row["api_success"] and row["json_parse_success"] and row["valid_label"] for row in rows)
    prompt_budget_ok = all(
        item.get("prompt_chars", 0) <= item.get("max_prompt_chars", 0)
        for mode in modes for item in manifest_rows(phase_dir, mode)
    )
    summary = {
        "phase": phase, "records": len(records), "calls": len(rows), "metrics": metrics,
        "tier_metrics": tier_metrics, "per_class": per_class, "rag_helpful": helpful,
        "rag_harmful": harmful, "rag_ties": len(paired) - helpful - harmful,
        "rag_disagreements": disagreements, "engineering_gate": engineering_gate,
        "prompt_budget_ok": prompt_budget_ok, "cost": cost,
    }
    write_json(phase_dir / "phase_summary.json", summary)
    lines = [
        f"# {phase.title()} paired evaluation", "", f"- Prompt version: `{PROMPT_VERSION}`",
        f"- Records: {len(records)}", f"- Calls: {len(rows) if args.run_api else preflight['calls']}",
        f"- Real API: {str(args.run_api).lower()}", f"- Engineering gate: {engineering_gate if args.run_api else 'not_run'}",
        f"- Prompt budget OK: {prompt_budget_ok}", "", "## Metrics", "",
        "| Mode | API success | JSON parse | Valid label | Technique accuracy | Stage accuracy |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for mode in modes:
        item = metrics[mode]
        lines.append(f"| {mode} | {fmt(item['api_success_rate'])} | {fmt(item['json_parse_success_rate'])} | {fmt(item['valid_label_rate'])} | {fmt(item['technique_accuracy'])} | {fmt(item['stage_accuracy'])} |")
    lines.extend(["", "## RAG effect", "", f"- Helpful: {helpful}", f"- Harmful: {harmful}", f"- Ties: {len(paired) - helpful - harmful}", f"- Prediction disagreements: {disagreements}"])
    (phase_dir / "small_api_eval_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (phase_dir / "rag_effect_report.md").write_text("\n".join(["# RAG effect", "", f"- Helpful: {helpful}", f"- Harmful: {harmful}", f"- Ties: {len(paired) - helpful - harmful}", ""] + [f"- `{row['record_id']}`: {row['rag_effect']}" for row in paired]) + "\n", encoding="utf-8")
    return summary


def run_phase(
    phase: str, subset: str, limit: int, all_records: list[dict[str, Any]],
    output_dir: Path, modes: list[str], args: argparse.Namespace,
) -> tuple[int, dict[str, Any]]:
    records = select_records(all_records, subset, limit, args.limit_per_class)
    if not records:
        raise ValueError(f"no records selected for {phase}/{subset}")
    phase_dir = output_dir / phase
    phase_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(phase_dir / "records_used.jsonl", records)
    profile = load_runtime_profile(args.runtime_profile, args.runtime_profiles)
    context_records = write_prompts(records, phase_dir, profile)
    base_url, model, api_key = api_env()
    context = {
        "phase": phase, "prompt_version": PROMPT_VERSION, "selected_record_ids": [row["record_id"] for row in records],
        "records": context_records, "runtime_profile": args.runtime_profile, "model": model,
        "base_url": base_url, "base_url_host": host_only(base_url), "run_api": args.run_api,
        "temperature": args.temperature, "max_output_tokens": args.max_output_tokens,
        "enable_thinking": False, "modes": modes,
    }
    write_json(phase_dir / "eval_context.json", context)
    estimate = estimate_phase_cost(phase_dir, modes, args.expected_output_tokens, args.input_price_per_million, args.output_price_per_million)
    preflight = safety_check(phase, records, base_url, model, api_key, estimate, args.run_api)
    write_json(phase_dir / "safe_preflight.json", preflight)
    if args.run_api:
        if os.environ.get("RUN_REAL_API_TEST") != "1":
            print("real API blocked: RUN_REAL_API_TEST=1 is required", file=sys.stderr)
            return 2, summarize_phase(phase, phase_dir, records, modes, preflight, args)
        if not base_url or not model or not api_key:
            print("real API blocked: base URL, model, or API key is missing", file=sys.stderr)
            return 2, summarize_phase(phase, phase_dir, records, modes, preflight, args)
        readiness = json.loads(args.readiness_report.read_text(encoding="utf-8")) if args.readiness_report.exists() else {}
        if not readiness.get("ready_for_tiny_real_eval"):
            print("real API blocked: passing readiness report is required", file=sys.stderr)
            return 2, summarize_phase(phase, phase_dir, records, modes, preflight, args)
        codes = [run_mode(mode, phase_dir, args) for mode in modes]
    else:
        codes = [0]
    summary = summarize_phase(phase, phase_dir, records, modes, preflight, args)
    return (0 if not any(codes) else 1), summary


def combined_report(output_dir: Path, smoke: dict[str, Any] | None, strict: dict[str, Any] | None, args: argparse.Namespace) -> str:
    main = strict or smoke or {}
    metrics = main.get("metrics", {})
    no_rag = metrics.get("no_rag", {})
    rag = metrics.get("rag", {})
    pcap = main.get("tier_metrics", {}).get("external_high_pcap", {}).get("rag", {})
    effect_ok = main.get("rag_harmful", 0) <= main.get("rag_helpful", 0) and (rag.get("technique_accuracy") or 0) >= (no_rag.get("technique_accuracy") or 0) - 0.1
    model_gate = bool(
        main.get("engineering_gate") and main.get("prompt_budget_ok")
        and (rag.get("stage_accuracy") or 0) >= 0.75
        and (rag.get("technique_accuracy") or 0) >= 0.60
        and effect_ok and (pcap.get("technique_accuracy") or 0) >= 2 / 3
    )
    per_class = main.get("per_class", {})
    lines = [
        "# Small online API evaluation: observable_boundary_rag_v3", "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        "- Purpose: guarded local/development evaluation on existing high-confidence public or controlled evidence.",
        "- Official `example-s3-0623` was not used; neither its samples nor answer table entered prompts or metrics.",
        f"- Real API executed: {str(args.run_api).lower()}", f"- Model: `{main.get('cost', {}).get('model')}`",
        f"- Base URL: `{main.get('cost', {}).get('base_url')}`", f"- Prompt version: `{PROMPT_VERSION}`",
        "- Stage codes were mapped deterministically from technique codes.", "",
        "## Experiment", "",
        f"- Smoke: {smoke.get('records', 0) if smoke else 0} records; engineering gate: {smoke.get('engineering_gate') if smoke else 'not_run'}.",
        f"- Strict: {strict.get('records', 0) if strict else 0} records; tiers limited to external_high_pcap/external_high_flow.",
        "- Medium and synthetic records were excluded from the main conclusion.", "",
        "## Strict results", "",
        "| Mode | API success | JSON parse | Valid label | Technique accuracy | Stage accuracy |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for mode in ("no_rag", "rag"):
        item = metrics.get(mode, {})
        lines.append(f"| {mode} | {fmt(item.get('api_success_rate'))} | {fmt(item.get('json_parse_success_rate'))} | {fmt(item.get('valid_label_rate'))} | {fmt(item.get('technique_accuracy'))} | {fmt(item.get('stage_accuracy'))} |")
    lines.extend(["", "## Per class", "", "| Technique | N | no-RAG | RAG |", "|---|---:|---:|---:|"])
    for code, values in per_class.items():
        n = values.get("rag", {}).get("calls", 0)
        lines.append(f"| `{code}` | {n} | {fmt(values.get('no_rag', {}).get('technique_accuracy'))} | {fmt(values.get('rag', {}).get('technique_accuracy'))} |")
    cost = main.get("cost", {})
    lines.extend([
        "", "## RAG effect", "", f"- Helpful: {main.get('rag_helpful', 0)}", f"- Harmful: {main.get('rag_harmful', 0)}",
        f"- Ties: {main.get('rag_ties', 0)}", f"- Prediction disagreements: {main.get('rag_disagreements', 0)}", "",
        "## Cost and latency", "", f"- Actual input/output tokens: {cost.get('actual_input_tokens', 0)} / {cost.get('actual_output_tokens', 0)}",
        f"- Estimated API cost: ${cost.get('actual_usd', 0):.6f}", f"- Mean observed latency: {cost.get('latency_seconds_mean')} seconds", "",
        "## Gate decision", "", f"- Engineering usability gate: **{'PASS' if main.get('engineering_gate') and main.get('prompt_budget_ok') else 'FAIL'}**",
        f"- Worth entering VM adaptation: **{'YES' if model_gate else 'NO'}**",
        "- This is a small readiness result, not a final quality claim.", "",
        "## Interpretation", "",
    ])
    if model_gate:
        lines.append("The strict high-confidence result clears the conservative next-stage thresholds. VM adaptation is reasonable, while retaining paired regression checks.")
    else:
        lines.append("The strict result does not clear all conservative quality thresholds. Continue prompt/RAG/session-card error analysis before VM adaptation.")
    lines.extend(["", "Detailed error attribution and individual helpful/harmful cases are in the output directory reports."])
    report = "\n".join(lines) + "\n"
    (output_dir / "small_api_eval_report.md").write_text(report, encoding="utf-8")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8")
    return report


def assert_no_key_leak(output_dir: Path, api_key: str | None) -> None:
    if not api_key or len(api_key) < 8:
        return
    for path in output_dir.rglob("*"):
        if not path.is_file() or path.stat().st_size > 10_000_000:
            continue
        if api_key in path.read_text(encoding="utf-8", errors="ignore"):
            raise RuntimeError(f"API key leak detected in {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run guarded smoke/strict/coverage paired API evaluation.")
    parser.add_argument("--records", type=Path, default=ROOT / "datasets/public_eval/real_api_candidate_records.jsonl")
    parser.add_argument("--subset", choices=["strict", "coverage", "custom"], default="strict")
    parser.add_argument("--phase", choices=["all", "smoke", "strict", "coverage"], default="all")
    parser.add_argument("--max-records", type=int, default=12, help="Strict/coverage record cap; smoke is always capped at 2.")
    parser.add_argument("--modes", default="no_rag,rag")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run-api", action="store_true")
    parser.add_argument("--model")
    parser.add_argument("--base-url")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-output-tokens", type=int, default=384)
    parser.add_argument("--expected-output-tokens", type=int, default=128)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit-per-class", type=int, default=3)
    parser.add_argument("--runtime-profiles", type=Path, default=DEFAULT_RUNTIME_PROFILES)
    parser.add_argument("--runtime-profile", default="nvidia_ubuntu_online_api")
    parser.add_argument("--readiness-report", type=Path, default=ROOT / "outputs/api_readiness/api_readiness_report.json")
    parser.add_argument("--disable-extra-body", action="store_true")
    parser.add_argument("--input-price-per-million", type=float, default=0.3)
    parser.add_argument("--output-price-per-million", type=float, default=2.4)
    parser.add_argument("--report", type=Path, default=ROOT / "docs/reports/small_online_api_eval_observable_v3.md")
    args = parser.parse_args()
    if args.dry_run and args.run_api:
        parser.error("--dry-run and --run-api are mutually exclusive")
    if args.phase == "strict" and not 8 <= args.max_records <= 12:
        parser.error("strict evaluation requires --max-records between 8 and 12")
    if args.phase == "coverage" and not 1 <= args.max_records <= 24:
        parser.error("coverage evaluation permits at most 24 records")
    if args.phase == "all" and not 8 <= args.max_records <= 12:
        parser.error("all requires a strict --max-records between 8 and 12")
    modes = [item.strip() for item in args.modes.split(",") if item.strip()]
    if not modes or any(mode not in {"no_rag", "rag"} for mode in modes):
        parser.error("--modes must contain no_rag and/or rag")
    load_env_file(ROOT / ".env")
    load_env_file(ROOT / ".env.local")
    if args.base_url:
        os.environ["OPENAI_BASE_URL"] = args.base_url
    if args.model:
        os.environ["OPENAI_MODEL"] = args.model
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir or ROOT / "outputs/api_eval" / f"small_eval_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    all_records = load_jsonl(args.records)
    smoke_summary = strict_summary = None
    exit_code = 0
    if args.phase in {"all", "smoke"}:
        code, smoke_summary = run_phase("smoke", "strict" if args.subset != "custom" else "custom", 2, all_records, output_dir, modes, args)
        exit_code = max(exit_code, code)
        if args.run_api and (code or not smoke_summary.get("engineering_gate") or not smoke_summary.get("prompt_budget_ok")):
            combined_report(output_dir, smoke_summary, None, args)
            assert_no_key_leak(output_dir, api_env()[2])
            print(json.dumps({"status": "stopped_after_smoke_failure", "output_dir": str(output_dir), "report": str(args.report)}))
            return 1
    if args.phase in {"all", "strict"}:
        code, strict_summary = run_phase("strict", "strict" if args.subset != "custom" else "custom", args.max_records, all_records, output_dir, modes, args)
        exit_code = max(exit_code, code)
    if args.phase == "coverage":
        code, strict_summary = run_phase("coverage", "coverage" if args.subset != "custom" else "custom", args.max_records, all_records, output_dir, modes, args)
        exit_code = max(exit_code, code)
    combined_report(output_dir, smoke_summary, strict_summary, args)
    assert_no_key_leak(output_dir, api_env()[2])
    print(json.dumps({"status": "complete" if exit_code == 0 else "completed_with_errors", "output_dir": str(output_dir), "report": str(args.report)}))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

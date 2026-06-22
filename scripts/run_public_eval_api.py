#!/usr/bin/env python3
"""Generate paired prompts and optionally run the public evaluation against an API."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from build_qwen35_session_prompts import PROMPT_VERSION, build_prompt
from build_rag_query import BOUNDARY_DOCS, detect_confusion_groups, record_terms
from qwen35_rag_utils import DEFAULT_RUNTIME_PROFILES, load_env_file, load_runtime_profile
from retrieve_rag import retrieve


ROOT = Path(__file__).resolve().parents[1]
def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def safe_name(record_id: str) -> str:
    return record_id.replace("/", "_").replace(":", "_")


def select_records(records: list[dict[str, Any]], max_records: int, max_per_class: int) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[record["technique_code"]].append(record)
    selected: list[dict[str, Any]] = []
    codes = sorted(groups)
    for index in range(max_per_class):
        for code in codes:
            if index < len(groups[code]) and len(selected) < max_records:
                selected.append(groups[code][index])
    return selected


def host_only(url: str | None) -> str:
    if not url:
        return "unknown"
    return urlparse(url).netloc or urlparse("http://" + url).netloc or "unknown"


def write_prompts(records: list[dict[str, Any]], output_dir: Path, profile: dict[str, Any]) -> dict[str, Any]:
    chunks = load_jsonl(ROOT / "rag/chunks/rag_chunks.jsonl")
    queries = []
    for item in records:
        evidence = item["classification_record"]
        terms, rules, low_signal = record_terms(evidence)
        confusion_groups = detect_confusion_groups(evidence)
        queries.append({
            "record_id": item["record_id"], "pcap_id": item["pcap_id"], "record_type": item["record_type"],
            "query": " ".join(terms), "query_terms": terms, "rules": rules, "low_signal": low_signal,
            "confusion_groups": confusion_groups,
            "targeted_boundary_doc_ids": [BOUNDARY_DOCS[group] for group in confusion_groups],
        })
    retrieval_rows = retrieve(queries, chunks, 5)
    retrieval_map = {item["record_id"]: item.get("snippets", []) for item in retrieval_rows}
    context_records: dict[str, Any] = {}
    for prompt_type in ("no_rag", "rag"):
        prompt_dir = output_dir / "prompts" / prompt_type
        prompt_dir.mkdir(parents=True, exist_ok=True)
        for old in prompt_dir.glob("*.txt"):
            old.unlink()
        manifest = []
        for item in records:
            snippets = None if prompt_type == "no_rag" else retrieval_map.get(item["record_id"], [])
            text, prompt_meta = build_prompt(item["classification_record"], "technique", snippets, profile)
            path = prompt_dir / f"{safe_name(item['record_id'])}.txt"
            path.write_text(text, encoding="utf-8")
            try:
                prompt_file = str(path.resolve().relative_to(ROOT))
            except ValueError:
                prompt_file = str(path)
            manifest.append({"record_id": item["record_id"], "prompt_file": prompt_file, "sha256": hashlib.sha256(text.encode()).hexdigest(), **prompt_meta})
            context_records.setdefault(item["record_id"], {})[f"{prompt_type}_prompt_sha256"] = manifest[-1]["sha256"]
            context_records[item["record_id"]][f"{prompt_type}_prompt_budget"] = prompt_meta
        (prompt_dir / "prompt_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for item in records:
        context_records.setdefault(item["record_id"], {})["retrieved_docs"] = retrieval_map.get(item["record_id"], [])
    (output_dir / "retrieval.json").write_text(json.dumps(retrieval_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return context_records


def api_env() -> tuple[str | None, str | None, str | None]:
    return (
        os.environ.get("BASE_URL") or os.environ.get("LLM_BASE_URL"),
        os.environ.get("MODEL") or os.environ.get("LLM_MODEL_NAME"),
        os.environ.get("API_KEY") or os.environ.get("LLM_API_KEY"),
    )


def run_one(prompt_type: str, output_dir: Path, count: int, args: argparse.Namespace) -> int:
    cmd = [
        sys.executable, str(ROOT / "scripts/run_qwen_openai_compatible.py"),
        "--prompt-dir", str(output_dir / "prompts" / prompt_type),
        "--output-dir", str(output_dir / "api" / prompt_type),
        "--result-name", "results.json", "--summary-name", "run_summary.md",
        "--max-files", str(count), "--temperature", "0", "--max-tokens", str(args.max_tokens),
        "--timeout-seconds", str(args.timeout_seconds), "--retries", str(args.retries),
        "--continue-on-error", "--require-run-api-flag", "--enable-thinking", "false",
        "--runtime-profile", args.runtime_profile,
        "--runtime-profiles", str(args.runtime_profiles),
    ]
    if args.disable_extra_body:
        cmd.append("--disable-extra-body")
    env = os.environ.copy()
    env["RUN_API"] = "1"
    return subprocess.run(cmd, cwd=ROOT, env=env, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare and optionally call paired public-eval prompts.")
    parser.add_argument("--eval-records", type=Path, default=ROOT / "datasets/public_eval/coverage_eval_records.jsonl")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/eval/rag_vs_no_rag")
    parser.add_argument("--run-api", action="store_true", help="Actually call the configured API; default is prompt-only dry-run.")
    parser.add_argument("--run-mock", action="store_true", help="Run paired prompts through dry_run_mock; no network/model call.")
    parser.add_argument("--runtime-profiles", type=Path, default=DEFAULT_RUNTIME_PROFILES)
    parser.add_argument("--runtime-profile", default=os.environ.get("RUNTIME_PROFILE", "ascend_openeuler_qwen35_27b"))
    parser.add_argument("--max-records", type=int, default=20)
    parser.add_argument("--max-per-class", type=int, default=5)
    parser.add_argument("--max-tokens", type=int, help="Completion budget; defaults to the selected runtime profile.")
    parser.add_argument("--timeout-seconds", type=float, default=180)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--disable-extra-body", action="store_true")
    args = parser.parse_args()
    if args.run_api and args.run_mock:
        parser.error("--run-api and --run-mock are mutually exclusive")
    load_env_file(ROOT / ".env")
    load_env_file(ROOT / ".env.local")
    if not 1 <= args.max_records <= 20:
        parser.error("--max-records must be between 1 and 20")
    if args.max_per_class < 1:
        parser.error("--max-per-class must be positive")
    records = select_records(load_jsonl(args.eval_records), args.max_records, args.max_per_class)
    if not records:
        raise ValueError("no public evaluation records selected")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.run_mock:
        args.runtime_profile = "dry_run_mock"
    profile = load_runtime_profile(args.runtime_profile, args.runtime_profiles)
    args.max_tokens = args.max_tokens if args.max_tokens is not None else int(profile.get("max_output_tokens", 384))
    context_records = write_prompts(records, args.output_dir, profile)
    base_url, model, api_key = api_env()
    context = {
        "prompt_version": PROMPT_VERSION,
        "selected_record_ids": [item["record_id"] for item in records],
        "records": context_records,
        "runtime_profile": args.runtime_profile,
        "model": profile.get("model") or model or "not_configured",
        "base_url_host": host_only(str(profile.get("base_url") or base_url or "")),
        "run_api": args.run_api,
        "run_mock": args.run_mock,
        "temperature": 0,
        "max_tokens": args.max_tokens,
        "enable_thinking": False,
        "extra_body_enabled": not args.disable_extra_body,
    }
    (args.output_dir / "eval_context.json").write_text(json.dumps(context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not args.run_api and not args.run_mock:
        print(f"dry-run complete: generated paired prompts for {len(records)} records; no API call made")
        return 0
    if args.run_api and (not base_url or not model or not api_key):
        print("--run-api requires BASE_URL/MODEL/API_KEY or LLM_BASE_URL/LLM_MODEL_NAME/LLM_API_KEY; no call made", file=sys.stderr)
        return 2
    return_codes = [run_one("no_rag", args.output_dir, len(records), args), run_one("rag", args.output_dir, len(records), args)]
    eval_cmd = [
        sys.executable, str(ROOT / "scripts/evaluate_rag_vs_no_rag.py"),
        "--eval-records", str(args.eval_records), "--context", str(args.output_dir / "eval_context.json"),
        "--no-rag-dir", str(args.output_dir / "api/no_rag"), "--rag-dir", str(args.output_dir / "api/rag"),
        "--output-dir", str(args.output_dir),
    ]
    eval_code = subprocess.run(eval_cmd, cwd=ROOT, check=False).returncode
    if any(return_codes) and not args.disable_extra_body:
        print("One or more API runs failed. If the online provider rejects chat_template_kwargs/extra_body, rerun with --disable-extra-body.", file=sys.stderr)
    return 0 if not any(return_codes) and eval_code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

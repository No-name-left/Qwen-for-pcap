#!/usr/bin/env python3
"""Estimate paired no-RAG/RAG token use and cost without calling an API."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from build_qwen35_session_prompts import PROMPT_VERSION, build_prompt
from build_rag_query import BOUNDARY_DOCS, detect_confusion_groups, record_terms
from qwen35_rag_utils import DEFAULT_RUNTIME_PROFILES, ROOT, load_runtime_profile
from retrieve_rag import retrieve


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def balanced(records: list[dict[str, Any]], limit: int, per_class: int | None = None) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[record["technique_code"]].append(record)
    selected = []
    max_depth = per_class if per_class is not None else max((len(rows) for rows in groups.values()), default=0)
    for index in range(max_depth):
        for code in sorted(groups):
            if index < len(groups[code]) and len(selected) < limit:
                selected.append(groups[code][index])
    return selected


def prompt_stats(records: list[dict[str, Any]], profile: dict[str, Any], chunks: list[dict[str, Any]]) -> dict[str, Any]:
    queries = []
    for item in records:
        terms, rules, low_signal = record_terms(item["classification_record"])
        groups = detect_confusion_groups(item["classification_record"])
        queries.append({
            "record_id": item["record_id"], "query": " ".join(terms), "query_terms": terms,
            "matched_rules": rules, "low_signal": low_signal, "confusion_groups": groups,
            "targeted_boundary_doc_ids": [BOUNDARY_DOCS[group] for group in groups],
        })
    retrieval = {row["record_id"]: row["snippets"] for row in retrieve(queries, chunks, top_k=5)}
    prompts = []
    for item in records:
        for kind, snippets in (("no_rag", None), ("rag", retrieval[item["record_id"]])):
            text, meta = build_prompt(item["classification_record"], "technique", snippets, profile)
            prompts.append({"kind": kind, "chars": len(text), "tokens": meta["estimated_prompt_tokens"]})
    return {
        "records": len(records), "calls": len(prompts),
        "average_prompt_chars": round(sum(row["chars"] for row in prompts) / len(prompts), 1) if prompts else 0,
        "average_input_tokens": round(sum(row["tokens"] for row in prompts) / len(prompts), 1) if prompts else 0,
        "total_input_tokens": sum(row["tokens"] for row in prompts),
        "no_rag_input_tokens": sum(row["tokens"] for row in prompts if row["kind"] == "no_rag"),
        "rag_input_tokens": sum(row["tokens"] for row in prompts if row["kind"] == "rag"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Estimate real API paired-evaluation tokens and provider cost.")
    parser.add_argument("--records", type=Path, default=ROOT / "datasets/public_eval/real_api_candidate_records.jsonl")
    parser.add_argument("--runtime-profiles", type=Path, default=DEFAULT_RUNTIME_PROFILES)
    parser.add_argument("--runtime-profile", default="ascend_openeuler_qwen35_27b")
    parser.add_argument("--expected-output-tokens", type=int, default=128, help="Expected short JSON completion tokens per call.")
    parser.add_argument("--input-price-per-million", type=float, default=0.3)
    parser.add_argument("--output-price-per-million", type=float, default=2.4)
    parser.add_argument("--report", type=Path, default=ROOT / "docs/reports/api_eval_cost_plan.md")
    args = parser.parse_args()
    if args.expected_output_tokens < 1 or args.input_price_per_million < 0 or args.output_price_per_million < 0:
        parser.error("token and price parameters must be non-negative (output tokens must be positive)")
    records = load_jsonl(args.records)
    profile = load_runtime_profile(args.runtime_profile, args.runtime_profiles)
    chunks = load_jsonl(ROOT / "rag/chunks/rag_chunks.jsonl")
    scenarios = {
        "smoke_5": balanced(records, 5),
        "per_class_tiny_3": balanced(records, len(records), per_class=3),
        "small_paired_10": balanced(records, min(10, len(records))),
        "medium_paired_20": balanced(records, min(20, len(records))),
    }
    results = {}
    for name, selected in scenarios.items():
        stats = prompt_stats(selected, profile, chunks)
        stats["expected_output_tokens_per_call"] = args.expected_output_tokens
        stats["total_output_tokens"] = stats["calls"] * args.expected_output_tokens
        stats["retry_costs"] = {}
        for retry in (0.0, 0.1, 0.2):
            multiplier = 1 + retry
            input_tokens = stats["total_input_tokens"] * multiplier
            output_tokens = stats["total_output_tokens"] * multiplier
            cost = input_tokens * args.input_price_per_million / 1_000_000 + output_tokens * args.output_price_per_million / 1_000_000
            stats["retry_costs"][f"{int(retry * 100)}%"] = {
                "input_tokens": round(input_tokens), "output_tokens": round(output_tokens), "estimated_usd": round(cost, 6),
            }
        results[name] = stats

    lines = [
        "# Real API paired-evaluation token and cost plan", "",
        f"- Candidate records: `{args.records.relative_to(ROOT) if args.records.is_absolute() and ROOT in args.records.parents else args.records}`",
        f"- Prompt version: `{PROMPT_VERSION}`", f"- Runtime profile: `{args.runtime_profile}`",
        f"- Thinking: off", f"- Expected output: {args.expected_output_tokens} tokens/call (profile maximum {profile.get('max_output_tokens')})",
        f"- Price parameters: input ${args.input_price_per_million}/1M, output ${args.output_price_per_million}/1M tokens", "",
        "| Scenario | Records | Calls | Avg chars | Avg input tokens | Total input | Total output | Cost 0% | Cost 10% | Cost 20% |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, stats in results.items():
        lines.append(
            f"| `{name}` | {stats['records']} | {stats['calls']} | {stats['average_prompt_chars']} | {stats['average_input_tokens']} | "
            f"{stats['total_input_tokens']} | {stats['total_output_tokens']} | ${stats['retry_costs']['0%']['estimated_usd']:.6f} | "
            f"${stats['retry_costs']['10%']['estimated_usd']:.6f} | ${stats['retry_costs']['20%']['estimated_usd']:.6f} |"
        )
    lines.extend(["", "## Retry sensitivity", "", "| Scenario | Failed/retried | Adjusted input tokens | Adjusted output tokens | Estimated USD |", "|---|---:|---:|---:|---:|"])
    for name, stats in results.items():
        for retry, values in stats["retry_costs"].items():
            lines.append(f"| `{name}` | {retry} | {values['input_tokens']} | {values['output_tokens']} | ${values['estimated_usd']:.6f} |")
    lines.extend([
        "", "## Assumptions and risks", "",
        "- Each selected record is called once no-RAG and once RAG.",
        "- Input tokens use the repository's conservative character estimator, not the provider tokenizer.",
        "- Thinking off is required. Thinking on may produce hidden/visible reasoning, longer output, schema failures and materially higher cost.",
        "- Prices are estimates only; use the provider's current pricing. Credits, billing, retries and actual completion length change the final charge.",
        "- HTTP 402 commonly indicates insufficient credits/billing and should stop a batch immediately.",
    ])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(results, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

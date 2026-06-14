#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from qwen35_rag_utils import ROOT
from retrieve_rag import retrieve


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run retrieval tests from retrieval_test_queries.jsonl.")
    parser.add_argument("--queries", type=Path, default=ROOT / "rag/metadata/retrieval_test_queries.jsonl")
    parser.add_argument("--chunks", type=Path, default=ROOT / "rag/chunks/rag_chunks.jsonl")
    parser.add_argument("--output-json", type=Path, default=ROOT / "rag/reports/qwen35_27b_rag_retrieval_test_results.json")
    parser.add_argument("--report", type=Path, default=ROOT / "rag/reports/qwen35_27b_rag_retrieval_test_report.md")
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args()
    queries = load_jsonl(args.queries)
    chunks = load_jsonl(args.chunks)
    retrieval_queries = [
        {"event_id": q["query_id"], "query_id": q["query_id"], "query": q["query"], "query_terms": q["query"].split()}
        for q in queries
    ]
    results = retrieve(retrieval_queries, chunks, args.top_k)
    by_id = {r["event_id"]: r for r in results}
    details = []
    passes = 0
    for q in queries:
        got = {s["doc_id"] for s in by_id[q["query_id"]]["snippets"]}
        expected = set(q.get("expected_doc_ids", []))
        hit = bool(got & expected)
        passes += int(hit)
        details.append({"query_id": q["query_id"], "query": q["query"], "expected_doc_ids": sorted(expected), "retrieved_doc_ids": sorted(got), "pass": hit})
    args.output_json.write_text(json.dumps(details, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Qwen3.5-27B RAG retrieval test report",
        "",
        f"- Queries: {len(details)}",
        f"- Passed: {passes}/{len(details)}",
        f"- Ready for retrieval test: {'yes' if passes == len(details) else 'needs_fix'}",
        "",
    ]
    for row in details:
        lines.append(f"## {row['query_id']}")
        lines.append(f"- pass: {row['pass']}")
        lines.append(f"- expected: {', '.join(row['expected_doc_ids'])}")
        lines.append(f"- retrieved: {', '.join(row['retrieved_doc_ids'][:10])}")
        lines.append("")
    args.report.write_text("\n".join(lines), encoding="utf-8")
    print(f"retrieval tests passed {passes}/{len(details)}")
    return 0 if passes == len(details) else 1


if __name__ == "__main__":
    raise SystemExit(main())

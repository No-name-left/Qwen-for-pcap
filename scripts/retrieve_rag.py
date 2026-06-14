#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from qwen35_rag_utils import ROOT, load_json, micro_path, tokenize


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def score_chunk(query: dict, chunk: dict) -> tuple[float, dict]:
    query_terms = query.get("query_terms", [])
    query_tokens = set(tokenize(" ".join(query_terms) + " " + query.get("query", "")))
    title_tokens = set(tokenize(chunk.get("title", "")))
    keyword_tokens = set(tokenize(" ".join(chunk.get("keywords", []))))
    text_tokens = set(tokenize(chunk.get("text", "")))
    category = chunk.get("category", "")
    attack_types = set(chunk.get("attack_type", []))
    attack_stages = set(chunk.get("attack_stage", []))

    exact_text = 0
    lower_blob = (chunk.get("title", "") + " " + " ".join(chunk.get("keywords", [])) + " " + chunk.get("text", "")).lower()
    for term in query_terms:
        t = str(term).lower()
        if len(t) >= 4 and t in lower_blob:
            exact_text += 1
    title_match = len(query_tokens & title_tokens)
    keyword_match = len(query_tokens & keyword_tokens)
    text_match = len(query_tokens & text_tokens)
    metadata_match = 0
    if "port_scan" in query_tokens or "scan" in query_tokens:
        metadata_match += 2 if "port_scan" in attack_types or "reconnaissance" in attack_stages else 0
    if "c2" in query_tokens or "cnc" in query_tokens or "command_and_control" in query_tokens:
        metadata_match += 2 if "c2" in attack_types or "command_and_control" in attack_stages else 0
    if "exploit" in query_tokens or "ms17-010" in query_tokens:
        metadata_match += 2 if "exploit" in attack_types or "initial_access" in attack_stages else 0
    if "protocol" in query_tokens and "anomaly" in query_tokens:
        metadata_match += 3 if category in {"false_positive_rules", "signatures", "protocols"} else 0
    if "low" in query_tokens and "confidence" in query_tokens:
        metadata_match += 2 if category == "false_positive_rules" else 0

    signature_bonus = 0
    for sig in ["strrat", "ms17-010", "doublepulsar", "sql injection", "xss", "dns tunnel"]:
        if sig in " ".join(query_terms).lower() and sig in lower_blob:
            signature_bonus += 8
    score = exact_text * 3 + title_match * 3 + keyword_match * 4 + min(text_match, 20) * 0.5 + metadata_match + signature_bonus
    return score, {
        "exact_phrase_matches": exact_text,
        "title_token_matches": title_match,
        "keyword_token_matches": keyword_match,
        "text_token_matches_capped": min(text_match, 20),
        "metadata_bonus": metadata_match,
        "signature_bonus": signature_bonus,
    }


def retrieve(queries: list[dict], chunks: list[dict], top_k: int) -> list[dict]:
    out = []
    for query in queries:
        scored = []
        for chunk in chunks:
            score, breakdown = score_chunk(query, chunk)
            if score > 0:
                scored.append((score, breakdown, chunk))
        scored.sort(key=lambda item: (-item[0], item[2]["doc_id"], item[2]["chunk_id"]))
        snippets = []
        for score, breakdown, chunk in scored[:top_k]:
            snippets.append(
                {
                    "chunk_id": chunk["chunk_id"],
                    "doc_id": chunk["doc_id"],
                    "title": chunk["title"],
                    "category": chunk["category"],
                    "score": round(score, 3),
                    "score_breakdown": breakdown,
                    "text": chunk["text"][:800],
                }
            )
        item_id = query.get("record_id", query.get("event_id", query.get("query_id")))
        out.append(
            {
                "record_id": item_id,
                "event_id": item_id,
                "pcap_id": query.get("pcap_id"),
                "record_type": query.get("record_type"),
                "query": query.get("query", ""),
                "query_terms": query.get("query_terms", []),
                "low_signal": query.get("low_signal", False),
                "snippets": snippets,
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Retrieve RAG snippets with keyword + metadata scoring.")
    parser.add_argument("--event-cards", type=Path, default=micro_path("outputs/event_cards/qwen_test_event_cards.json"))
    parser.add_argument("--queries", type=Path, default=ROOT / "outputs/rag_queries/qwen35_session_records_rag_queries.jsonl")
    parser.add_argument("--chunks", type=Path, default=ROOT / "rag/chunks/rag_chunks.jsonl")
    parser.add_argument("--index", type=Path, default=ROOT / "rag/index/keyword_index.json")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/rag_retrieval/qwen35_session_records_retrieved_knowledge_top5.json")
    parser.add_argument("--report", type=Path, default=ROOT / "outputs/rag_retrieval/qwen35_session_records_retrieval_report_top5.md")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--retriever-mode", default="keyword", choices=["keyword", "vector", "hybrid"])
    args = parser.parse_args()
    if args.retriever_mode != "keyword":
        raise ValueError("only keyword retriever mode is implemented in this baseline")
    queries = load_jsonl(args.queries)
    chunks = load_jsonl(args.chunks)
    results = retrieve(queries, chunks, args.top_k)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Qwen3.5-27B session-record RAG retrieval report",
        "",
        f"- Retriever mode: {args.retriever_mode}",
        f"- Top K: {args.top_k}",
        f"- Records: {len(results)}",
        f"- Output: `{args.output.relative_to(ROOT)}`",
        "",
    ]
    for item in results[:60]:
        lines.append(f"## {item['record_id']}")
        lines.append("")
        lines.append(f"- low_signal: {item.get('low_signal')}")
        lines.append(f"- query_terms: {', '.join(map(str, item.get('query_terms', [])[:30]))}")
        for snip in item["snippets"]:
            lines.append(f"- {snip['doc_id']} / {snip['chunk_id']}: score={snip['score']}; breakdown={snip['score_breakdown']}")
        lines.append("")
    args.report.write_text("\n".join(lines), encoding="utf-8")
    print(f"retrieved snippets for {len(results)} queries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

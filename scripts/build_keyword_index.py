#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from qwen35_rag_utils import ROOT, tokenize


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an explainable keyword index over RAG chunks.")
    parser.add_argument("--chunks", type=Path, default=ROOT / "rag/chunks/rag_chunks.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "rag/index/keyword_index.json")
    parser.add_argument("--report", type=Path, default=ROOT / "rag/index/keyword_index_report.md")
    args = parser.parse_args()
    if not args.chunks.exists():
        raise FileNotFoundError(f"missing chunks file: {args.chunks}")

    chunks = [json.loads(line) for line in args.chunks.read_text(encoding="utf-8").splitlines() if line.strip()]
    inverted: dict[str, dict[str, int]] = defaultdict(dict)
    chunk_meta: dict[str, dict] = {}
    for chunk in chunks:
        cid = chunk["chunk_id"]
        fields = [
            chunk["doc_id"],
            chunk["title"],
            chunk["category"],
            " ".join(chunk.get("keywords", [])),
            " ".join(chunk.get("attack_type", [])),
            " ".join(chunk.get("attack_stage", [])),
            chunk["text"],
        ]
        tokens = tokenize(" ".join(fields))
        counts = defaultdict(int)
        for token in tokens:
            counts[token] += 1
        for token, count in counts.items():
            inverted[token][cid] = count
        chunk_meta[cid] = {
            "doc_id": chunk["doc_id"],
            "title": chunk["title"],
            "category": chunk["category"],
            "keywords": chunk.get("keywords", []),
            "attack_type": chunk.get("attack_type", []),
            "attack_stage": chunk.get("attack_stage", []),
            "source_file": chunk["source_file"],
        }

    index = {"version": 1, "chunk_count": len(chunks), "token_count": len(inverted), "inverted_index": inverted, "chunk_meta": chunk_meta}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Keyword index report",
        "",
        f"- Input chunks: `{args.chunks.relative_to(ROOT)}`",
        f"- Indexed chunks: {len(chunks)}",
        f"- Unique tokens: {len(inverted)}",
        f"- Output: `{args.output.relative_to(ROOT)}`",
        "",
        "## Retrieval mode",
        "",
        "- Current mode: keyword.",
        "- Future modes reserved: vector, hybrid.",
    ]
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"indexed {len(chunks)} chunks with {len(inverted)} tokens")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

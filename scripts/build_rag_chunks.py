#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from qwen35_rag_utils import ROOT, parse_markdown_front_matter


def split_units(body: str) -> list[str]:
    lines = body.splitlines()
    units: list[str] = []
    buf: list[str] = []
    for line in lines:
        if line.startswith("#"):
            if buf:
                units.append("\n".join(buf).strip())
                buf = []
            units.append(line.strip())
            continue
        if not line.strip():
            if buf:
                units.append("\n".join(buf).strip())
                buf = []
            continue
        buf.append(line)
    if buf:
        units.append("\n".join(buf).strip())
    return [u for u in units if u]


def word_count(text: str) -> int:
    return len(re.findall(r"[A-Za-z0-9_.:/+-]+|[\u4e00-\u9fff]", text))


def build_chunks_for_doc(path: Path, root: Path) -> list[dict]:
    meta, body = parse_markdown_front_matter(path)
    units = split_units(body)
    chunks: list[dict] = []
    current: list[str] = []
    for unit in units:
        if current and word_count("\n\n".join(current + [unit])) > 180:
            chunks.append({"text": "\n\n".join(current).strip()})
            current = [unit]
        else:
            current.append(unit)
        if word_count("\n\n".join(current)) >= 80:
            chunks.append({"text": "\n\n".join(current).strip()})
            current = []
    if current:
        if chunks and word_count("\n\n".join([chunks[-1]["text"], *current])) <= 220:
            chunks[-1]["text"] = "\n\n".join([chunks[-1]["text"], *current]).strip()
        else:
            chunks.append({"text": "\n\n".join(current).strip()})

    out = []
    rel = str(path.relative_to(root))
    for idx, chunk in enumerate(chunks, start=1):
        out.append(
            {
                "chunk_id": f"{meta['doc_id']}__chunk_{idx:03d}",
                "doc_id": meta["doc_id"],
                "source_file": rel,
                "category": meta["category"],
                "title": meta["title"],
                "keywords": meta.get("keywords", []),
                "attack_type": meta.get("attack_types", []),
                "attack_stage": meta.get("attack_stages", []),
                "text": chunk["text"],
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Build RAG chunks from Markdown knowledge files.")
    parser.add_argument("--knowledge-dir", type=Path, default=ROOT / "rag/knowledge")
    parser.add_argument("--output", type=Path, default=ROOT / "rag/chunks/rag_chunks.jsonl")
    parser.add_argument("--report", type=Path, default=ROOT / "rag/chunks/rag_chunks_report.md")
    args = parser.parse_args()

    docs = sorted(args.knowledge_dir.glob("**/*.md"))
    chunks = []
    for path in docs:
        chunks.extend(build_chunks_for_doc(path, ROOT))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(chunk, ensure_ascii=False, sort_keys=True) + "\n")

    by_cat: dict[str, int] = {}
    for chunk in chunks:
        by_cat[chunk["category"]] = by_cat.get(chunk["category"], 0) + 1
    lines = [
        "# RAG chunks report",
        "",
        f"- Source documents: {len(docs)}",
        f"- Chunks generated: {len(chunks)}",
        f"- Output: `{args.output.relative_to(ROOT)}`",
        "",
        "## Chunks by category",
        "",
        *[f"- {k}: {v}" for k, v in sorted(by_cat.items())],
    ]
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(chunks)} chunks from {len(docs)} docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

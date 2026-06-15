#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from build_qwen35_session_prompts import prompt_text
from qwen35_rag_utils import ROOT, load_json


def load_retrieval(path: Path) -> dict[str, list[dict[str, Any]]]:
    data = load_json(path) if path.exists() else []
    return {item.get("record_id"): item.get("snippets", []) for item in data if item.get("record_id")}


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prompt_name(record_id: str) -> str:
    return record_id.replace("/", "_").replace(":", "_") + ".txt"


def ctu_score(record: dict[str, Any], retrieval_query: str) -> int:
    score = 0
    text = retrieval_query.lower()
    if "c2" in text or "callback" in text or "botnet" in text or "irc" in text:
        score += 5
    if record.get("src_ip") == "147.32.84.165":
        score += 3
    if record.get("dst_port") in {80, 443, 65520, 3128, 53}:
        score += 1
    if (record.get("duration") or 0) > 60:
        score += 1
    if record.get("dns_summary"):
        queries = " ".join(record.get("dns_summary", {}).get("queries", []))
        if any(token in queries for token in ["irc", "nocomcom", "mewgost", "coolnuff"]):
            score += 4
    return score


def normal_score(record: dict[str, Any], retrieval_query: str) -> int:
    score = 0
    text = retrieval_query.lower()
    if "normal" in text or "weak-only" in text or "tn01_01" in text:
        score += 4
    if record.get("src_ip") != "147.32.84.165":
        score += 2
    if (record.get("same_src_failed_conn_rate") or 0) == 0:
        score += 1
    if (record.get("same_src_unique_dst_ports") or 0) <= 15:
        score += 1
    return score


def select_records(
    ctu_records: list[dict[str, Any]],
    portscan_records: list[dict[str, Any]],
    ctu_queries: dict[str, str],
) -> tuple[list[dict[str, Any]], list[str]]:
    notes: list[str] = []
    selected: list[dict[str, Any]] = []
    scan_groups = [r for r in portscan_records if r.get("record_type") == "scan_group"]
    if not scan_groups:
        raise RuntimeError("no portscan scan_group record found")
    selected.append(scan_groups[0])

    botnet_ranked = sorted(
        ctu_records,
        key=lambda r: (ctu_score(r, ctu_queries.get(r.get("record_id", ""), "")), r.get("record_id", "")),
        reverse=True,
    )
    botnet = botnet_ranked[:4]
    selected.extend(botnet)

    botnet_ids = {r.get("record_id") for r in botnet}
    normal_ranked = sorted(
        [r for r in ctu_records if r.get("record_id") not in botnet_ids],
        key=lambda r: (normal_score(r, ctu_queries.get(r.get("record_id", ""), "")), r.get("record_id", "")),
        reverse=True,
    )
    normal = normal_ranked[:5]
    selected.extend(normal)

    notes.append("CTU botnet-like and normal-like records were selected by heuristic evidence from RAG query text, traffic fields, and the public CTU label-reference boundary; labels were not written into prompts.")
    notes.append(f"Selected {len(botnet)} CTU botnet/C2-like candidates and {len(normal)} normal-like candidates plus one portscan scan_group.")
    return selected[:10], notes


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a capped mixed small API test set and RAG prompts.")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/api_tests/mixed_small")
    parser.add_argument("--ctu-records", type=Path, default=ROOT / "outputs/session_cards/feasibility/classification_records_all.json")
    parser.add_argument("--portscan-records", type=Path, default=ROOT / "outputs/session_cards/feasibility_portscan/classification_records_all.json")
    parser.add_argument("--ctu-retrieval", type=Path, default=ROOT / "outputs/rag_retrieval/feasibility/qwen35_session_records_retrieved_knowledge_top5.json")
    parser.add_argument("--portscan-retrieval", type=Path, default=ROOT / "outputs/rag_retrieval/feasibility_portscan/qwen35_session_records_retrieved_knowledge_top5.json")
    args = parser.parse_args()

    ctu_records = load_json(args.ctu_records)
    portscan_records = load_json(args.portscan_records)
    ctu_retrieval_items = load_json(args.ctu_retrieval)
    ctu_retrieval = load_retrieval(args.ctu_retrieval)
    portscan_retrieval = load_retrieval(args.portscan_retrieval)
    ctu_queries = {item.get("record_id"): item.get("query", "") for item in ctu_retrieval_items}

    selected, notes = select_records(ctu_records, portscan_records, ctu_queries)
    selected_ids = {r["record_id"] for r in selected}
    selected_retrieval = {**ctu_retrieval, **portscan_retrieval}

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "selected_records.json", selected)

    for prompt_dir_name, task in [("prompts_technique_rag", "technique"), ("prompts_stage_rag", "stage")]:
        prompt_dir = args.output_dir / prompt_dir_name
        prompt_dir.mkdir(parents=True, exist_ok=True)
        for old in prompt_dir.glob("*.txt"):
            old.unlink()
        manifest = []
        for record in selected:
            rid = record["record_id"]
            snippets = selected_retrieval.get(rid, [])
            path = prompt_dir / prompt_name(rid)
            path.write_text(prompt_text(record, task, snippets), encoding="utf-8")
            manifest.append({"record_id": rid, "prompt_file": str(path.relative_to(ROOT)), "snippet_count": len(snippets)})
        write_json(prompt_dir / "prompt_manifest.json", manifest)

    scan_group_present = any(r.get("record_type") == "scan_group" for r in selected)
    session_present = any(r.get("record_type") == "session" for r in selected)
    selection_lines = [
        "# Mixed small API test selection report",
        "",
        f"- Selected records: {len(selected)}",
        f"- Contains portscan scan_group: {str(scan_group_present).lower()}",
        f"- Contains session records: {str(session_present).lower()}",
        "",
        "## Selection Notes",
        "",
        *[f"- {note}" for note in notes],
        "",
        "## Records",
        "",
    ]
    for record in selected:
        tag = "portscan_scan_group" if record.get("record_type") == "scan_group" else "ctu_candidate"
        selection_lines.append(f"- {record['record_id']} | {record.get('record_type')} | {tag}")
    (args.output_dir / "selection_report.md").write_text("\n".join(selection_lines) + "\n", encoding="utf-8")

    prompt_lines = [
        "# Mixed small prompt subset report",
        "",
        f"- Selected records: {len(selected)}",
        f"- Technique RAG prompts: {len(list((args.output_dir / 'prompts_technique_rag').glob('*.txt')))}",
        f"- Stage RAG prompts: {len(list((args.output_dir / 'prompts_stage_rag').glob('*.txt')))}",
        f"- Contains scan_group and session: {str(scan_group_present and session_present).lower()}",
        "- RAG prompts include retrieved knowledge snippets from the feasibility retrieval outputs.",
        "- Technique allowed codes: `TA43_01`, `TA43_02`, `TA01_01`, `TA01_02`, `TA03_01`, `TA11_01`, `TA11_02`, `TN01_01`.",
        "- Stage allowed codes: `TA43`, `TA01`, `TA03`, `TA11`, `TN01`.",
        "- Public labels or local generated labels are not written into prompts.",
    ]
    (args.output_dir / "prompt_subset_report.md").write_text("\n".join(prompt_lines) + "\n", encoding="utf-8")
    print(f"built mixed small set with {len(selected_ids)} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

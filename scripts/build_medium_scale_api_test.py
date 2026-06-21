#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from build_qwen35_session_prompts import prompt_text
from qwen35_rag_utils import ROOT


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_retrieval(path: Path) -> dict[str, list[dict[str, Any]]]:
    data = load_json(path) if path.exists() else []
    return {item.get("record_id"): item.get("snippets", []) for item in data if item.get("record_id")}


def load_queries(path: Path) -> dict[str, str]:
    data = load_json(path) if path.exists() else []
    return {item.get("record_id"): item.get("query", "") for item in data if item.get("record_id")}


def prompt_name(record_id: str) -> str:
    return record_id.replace("/", "_").replace(":", "_") + ".txt"


def join_ctu_public_labels(records: list[dict[str, Any]], label_path: Path) -> dict[str, dict[str, Any]]:
    key_to_records: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for record in records:
        src = str(record.get("src_ip"))
        sport = str(record.get("src_port"))
        dst = str(record.get("dst_ip"))
        dport = str(record.get("dst_port"))
        key_to_records.setdefault((src, sport, dst, dport), []).append(record)
        key_to_records.setdefault((dst, dport, src, sport), []).append(record)

    counts: dict[str, dict[str, int]] = {record["record_id"]: {} for record in records}
    if label_path.exists():
        with label_path.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                key = (row.get("SrcAddr", ""), row.get("Sport", "").strip(), row.get("DstAddr", ""), row.get("Dport", "").strip())
                candidates = key_to_records.get(key)
                if not candidates:
                    continue
                label = row.get("Label", "")
                for record in candidates:
                    rid = record["record_id"]
                    counts[rid][label] = counts[rid].get(label, 0) + 1

    refs: dict[str, dict[str, Any]] = {}
    for rid, label_counts in counts.items():
        if not label_counts:
            refs[rid] = {
                "reference_code": None,
                "reference_family": "unknown",
                "reference_quality": "unmatched",
                "top_public_label": None,
                "matched_label_rows": 0,
            }
            continue
        top_label, top_count = sorted(label_counts.items(), key=lambda item: (-item[1], item[0]))[0]
        if "From-Botnet" in top_label:
            code, family, quality = "TA11_02", "ctu_botnet_like", "high"
        elif "From-Normal" in top_label:
            code, family, quality = "TN01_01", "ctu_normal_like", "medium"
        elif "Background" in top_label:
            code, family, quality = "TN01_01", "ctu_background_like", "low"
        else:
            code, family, quality = None, "unknown", "unknown"
        refs[rid] = {
            "reference_code": code,
            "reference_family": family,
            "reference_quality": quality,
            "top_public_label": top_label,
            "matched_label_rows": top_count,
        }
    return refs


def botnet_score(record: dict[str, Any], query: str, ref: dict[str, Any]) -> int:
    text = query.lower()
    score = 0
    if ref.get("reference_family") == "ctu_botnet_like":
        score += 10
    if any(token in text for token in ("c2", "callback", "botnet", "irc", "command_and_control", "ta11_02")):
        score += 4
    if record.get("dst_port") in {6667, 65520, 80, 443, 3128}:
        score += 1
    if record.get("src_ip") == "147.32.84.165":
        score += 2
    if (record.get("duration") or 0) > 60:
        score += 1
    return score


def normal_like_score(record: dict[str, Any], query: str, ref: dict[str, Any]) -> int:
    text = query.lower()
    score = 0
    if any(token in text for token in ("normal business", "weak-only", "tn01_01")):
        score += 6
    if ref.get("reference_family") in {"ctu_normal_like", "ctu_background_like"}:
        score += 4
    if (record.get("same_src_failed_conn_rate") or 0) == 0:
        score += 1
    if (record.get("same_src_unique_dst_ports") or 999) <= 15:
        score += 1
    if (record.get("orig_pkts") or 0) <= 10:
        score += 1
    return score


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a capped medium-scale public-feasibility API test set.")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs/api_tests/medium_scale")
    parser.add_argument("--ctu-records", type=Path, default=ROOT / "outputs/session_cards/feasibility/classification_records_all.json")
    parser.add_argument("--portscan-records", type=Path, default=ROOT / "outputs/session_cards/feasibility_portscan/classification_records_all.json")
    parser.add_argument("--ctu-retrieval", type=Path, default=ROOT / "outputs/rag_retrieval/feasibility/qwen35_session_records_retrieved_knowledge_top5.json")
    parser.add_argument("--portscan-retrieval", type=Path, default=ROOT / "outputs/rag_retrieval/feasibility_portscan/qwen35_session_records_retrieved_knowledge_top5.json")
    parser.add_argument("--ctu-labels", type=Path, default=ROOT / "datasets/public/ctu13/labels/capture20110810.binetflow")
    args = parser.parse_args()

    ctu_records = load_json(args.ctu_records)
    portscan_records = load_json(args.portscan_records)
    ctu_retrieval = load_retrieval(args.ctu_retrieval)
    portscan_retrieval = load_retrieval(args.portscan_retrieval)
    ctu_queries = load_queries(args.ctu_retrieval)
    ctu_refs = join_ctu_public_labels(ctu_records, args.ctu_labels)

    scan_groups = [record for record in portscan_records if record.get("record_type") == "scan_group"]
    portscan_sessions = [record for record in portscan_records if record.get("record_type") == "session"][:5]
    if not scan_groups:
        raise RuntimeError("no portscan scan_group found")

    botnet_ranked = sorted(
        ctu_records,
        key=lambda record: (
            botnet_score(record, ctu_queries.get(record["record_id"], ""), ctu_refs.get(record["record_id"], {})),
            record["record_id"],
        ),
        reverse=True,
    )
    botnet = botnet_ranked[:45]
    botnet_ids = {record["record_id"] for record in botnet}
    normal_ranked = sorted(
        [record for record in ctu_records if record["record_id"] not in botnet_ids],
        key=lambda record: (
            normal_like_score(record, ctu_queries.get(record["record_id"], ""), ctu_refs.get(record["record_id"], {})),
            record["record_id"],
        ),
        reverse=True,
    )
    normal_like = normal_ranked[:45]

    selected = [scan_groups[0], *portscan_sessions, *botnet, *normal_like]
    if len(selected) > 100:
        selected = selected[:100]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "selected_records.json", selected)
    (args.output_dir / "selected_record_ids.txt").write_text("\n".join(record["record_id"] for record in selected) + "\n", encoding="utf-8")

    reference: dict[str, dict[str, Any]] = {}
    for record in selected:
        rid = record["record_id"]
        if record.get("pcap_id") == "feasibility_portscan" and record.get("record_type") == "scan_group":
            reference[rid] = {"reference_code": "TA43_01", "reference_family": "portscan_scan_group", "reference_quality": "high_controlled"}
        elif record.get("pcap_id") == "feasibility_portscan":
            reference[rid] = {"reference_code": None, "reference_family": "portscan_session_context", "reference_quality": "not_evaluated"}
        else:
            ref = ctu_refs.get(rid, {"reference_code": None, "reference_family": "unknown", "reference_quality": "unmatched"})
            role = "ctu_botnet_like" if rid in botnet_ids else "ctu_normal_like_heuristic"
            reference[rid] = {**ref, "selection_role": role}
            if role == "ctu_normal_like_heuristic" and ref.get("reference_family") != "ctu_normal_like":
                reference[rid]["reference_quality"] = "heuristic_not_reliable_for_normal"
    write_json(args.output_dir / "public_reference_labels.json", reference)

    retrieval = {**ctu_retrieval, **portscan_retrieval}
    prompt_counts: dict[str, int] = {}
    for prompt_dir_name, task in [("prompts_technique_rag", "technique")]:
        prompt_dir = args.output_dir / prompt_dir_name
        prompt_dir.mkdir(parents=True, exist_ok=True)
        for old in prompt_dir.glob("*.txt"):
            old.unlink()
        manifest = []
        for record in selected:
            rid = record["record_id"]
            path = prompt_dir / prompt_name(rid)
            snippets = retrieval.get(rid, [])
            path.write_text(prompt_text(record, task, snippets), encoding="utf-8")
            manifest.append({"record_id": rid, "prompt_file": str(path.relative_to(ROOT)), "snippet_count": len(snippets)})
        write_json(prompt_dir / "prompt_manifest.json", manifest)
        prompt_counts[prompt_dir_name] = len(manifest)

    missing_categories = ["TA43_02", "TA03_01", "TA11_01"]
    reliable_normal_count = sum(1 for record in normal_like if ctu_refs.get(record["record_id"], {}).get("reference_family") == "ctu_normal_like")
    write_text(
        args.output_dir / "selection_report.md",
        [
            "# Medium-scale selection report",
            "",
            f"- Total records: {len(selected)}",
            f"- Portscan scan_group records: {sum(1 for record in selected if record.get('record_type') == 'scan_group')}",
            f"- Portscan ordinary session records: {len(portscan_sessions)}",
            f"- CTU botnet-like records: {len(botnet)}",
            f"- CTU normal-like heuristic records: {len(normal_like)}",
            f"- Reliable public CTU normal labels in selected normal-like set: {reliable_normal_count}",
            "- Label reference reliability: partial. Botnet reference is reliable for joined `From-Botnet*` rows; normal-like selection is heuristic because the available CTU feasibility subset does not contain enough `From-Normal*` joins.",
            f"- Missing covered categories: {', '.join(missing_categories)}",
            "- Public labels are stored only in metadata/evaluation outputs and are not written into prompts.",
        ],
    )
    write_text(
        args.output_dir / "prompt_subset_report.md",
        [
            "# Medium-scale prompt subset report",
            "",
            f"- Selected records: {len(selected)}",
            f"- Technique RAG prompts: {prompt_counts['prompts_technique_rag']}",
            "- Contains session and scan_group records: true",
            "- RAG prompts include retrieved knowledge snippets from feasibility retrieval outputs.",
            "- Technique allowed codes: `TA43_01`, `TA43_02`, `TA01_01`, `TA01_02`, `TA03_01`, `TA11_01`, `TA11_02`, `TN01_01`.",
            "- Stage prompts are not generated; stage codes are derived from technique codes.",
            "- Prompt records exclude `candidate_hint` and do not include public label reference answers.",
        ],
    )
    print(f"built medium-scale set with {len(selected)} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

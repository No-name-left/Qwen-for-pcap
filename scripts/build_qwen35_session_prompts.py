#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from qwen35_rag_utils import REAL_MICRO_DIR, ROOT, load_json


STAGE_CODES = ["TA43", "TA01", "TA03", "TA11", "TN01"]
TECHNIQUE_CODES = ["TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"]


def load_retrieval(path: Path) -> dict[str, list[dict[str, Any]]]:
    if not path.exists():
        return {}
    data = load_json(path)
    return {item.get("record_id") or item.get("event_id"): item.get("snippets", []) for item in data}


def display_path(path: Path) -> str:
    resolved = path.resolve()
    for base in (ROOT, REAL_MICRO_DIR):
        try:
            return str(resolved.relative_to(base))
        except ValueError:
            continue
    return str(path)


def compact_record(record: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "record_id",
        "session_id",
        "pcap_id",
        "record_type",
        "parser_source",
        "start_time",
        "end_time",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "proto",
        "service",
        "duration",
        "orig_pkts",
        "resp_pkts",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
        "history",
        "suricata_evidence_available",
        "related_suricata_alerts",
        "http_summary",
        "dns_summary",
        "tls_summary",
        "same_src_conn_count",
        "same_src_unique_dst_ports",
        "same_src_unique_dst_ips",
        "same_src_failed_conn_rate",
        "same_dst_unique_src_count",
        "same_src_same_dst_port_count",
        "time_window_neighbor_alert_count",
        "session_count",
        "unique_dst_ports",
        "dst_ports_sample",
        "failed_conn_rate",
    ]
    return {key: record.get(key) for key in keys if key in record}


def prompt_text(record: dict[str, Any], task: str, snippets: list[dict[str, Any]] | None) -> str:
    allowed = STAGE_CODES if task == "stage" else TECHNIQUE_CODES
    code_field = "stage_code" if task == "stage" else "technique_code"
    rag_block = ""
    if snippets is not None:
        trimmed = [
            {
                "doc_id": s.get("doc_id"),
                "title": s.get("title"),
                "score": s.get("score"),
                "text": s.get("text"),
            }
            for s in snippets[:5]
        ]
        rag_block = "\nRAG_TOP5_SNIPPETS:\n" + json.dumps(trimmed, ensure_ascii=False, indent=2)
    return (
        "You are classifying one PCAP network-flow classification record for a security competition.\n"
        "Return exactly one JSON object and no markdown.\n"
        "Do not use IP/domain reputation. Do not use context from other PCAP files. Do not output legacy labels.\n"
        "Evidence-first policy: classify from CLASSIFICATION_RECORD first; use RAG only to clarify official-code boundaries.\n"
        "If record evidence is weak, ambiguous, or ordinary background/business traffic, choose TN01_01.\n"
        "Do not classify C2 or exploit from DNS/NBNS, short connections, generic outbound traffic, or a single weak feature alone.\n"
        "However, do not overuse TN01_01 when multiple strong fields jointly indicate attack behavior, such as many outbound connections from one source, high failed-connection context, repeated callback-like services, or scan_group fanout.\n"
        "Prefer TA43_01 only for multi-port fanout/SYN or failed-connection scan evidence; prefer TA43_02 for service-specific vulnerability probing without exploit payload.\n"
        "Prefer TA01_02 only when exploit payload, CVE attempt, command injection, SQL/XSS payload, or abnormal exploit response evidence exists.\n"
        "Use TA11_02 for compromised-host outbound callback/beacon evidence; TA11_01 for operator access to an existing backdoor; TA03_01 for installation/persistence/dropper evidence.\n"
        f"Allowed {code_field} values: {', '.join(allowed)}.\n"
        "The JSON object must contain exactly these fields:\n"
        "{\n"
        '  "record_id": string,\n'
        '  "pcap_id": string,\n'
        '  "record_type": "session" or "scan_group",\n'
        '  "start_time": number or null,\n'
        '  "end_time": number or null,\n'
        '  "src_ip": string or null,\n'
        '  "src_port": number/string/null,\n'
        '  "dst_ip": string or null,\n'
        '  "dst_port": number/string/null,\n'
        f'  "predicted_code": one of {allowed},\n'
        '  "confidence": number between 0 and 1,\n'
        '  "reason": one short sentence\n'
        "}\n"
        "For weak or ambiguous evidence, use the normal code.\n"
        f"{rag_block}\n"
        "CLASSIFICATION_RECORD:\n"
        f"{json.dumps(compact_record(record), ensure_ascii=False, indent=2)}\n"
    )


def write_prompt_set(records: list[dict[str, Any]], out_dir: Path, task: str, retrieval: dict[str, list[dict[str, Any]]] | None) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for record in records:
        record_id = record["record_id"]
        snippets = retrieval.get(record_id, []) if retrieval is not None else None
        path = out_dir / f"{record_id.replace('/', '_').replace(':', '_')}.txt"
        path.write_text(prompt_text(record, task, snippets), encoding="utf-8")
        manifest.append({"record_id": record_id, "prompt_file": display_path(path)})
    (out_dir / "prompt_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Qwen3.5-27B session-level official-code prompts without calling an API.")
    parser.add_argument("--records", type=Path, default=ROOT / "outputs/session_cards/classification_records_all.json")
    parser.add_argument("--retrieval", type=Path, default=ROOT / "outputs/rag_retrieval/qwen35_session_records_retrieved_knowledge_top5.json")
    parser.add_argument("--micro-output-dir", type=Path, default=REAL_MICRO_DIR / "outputs")
    parser.add_argument("--report", type=Path, default=REAL_MICRO_DIR / "outputs/prompts_qwen35_27b_prompt_report.md")
    args = parser.parse_args()

    records = load_json(args.records) if args.records.exists() else []
    retrieval = load_retrieval(args.retrieval)
    counts = {
        "prompts_qwen35_27b_stage_no_rag": write_prompt_set(records, args.micro_output_dir / "prompts_qwen35_27b_stage_no_rag", "stage", None),
        "prompts_qwen35_27b_stage_rag": write_prompt_set(records, args.micro_output_dir / "prompts_qwen35_27b_stage_rag", "stage", retrieval),
        "prompts_qwen35_27b_technique_no_rag": write_prompt_set(records, args.micro_output_dir / "prompts_qwen35_27b_technique_no_rag", "technique", None),
        "prompts_qwen35_27b_technique_rag": write_prompt_set(records, args.micro_output_dir / "prompts_qwen35_27b_technique_rag", "technique", retrieval),
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Qwen3.5-27B prompt generation report",
        "",
        f"- Input classification records: `{args.records.relative_to(ROOT)}`",
        f"- Records: {len(records)}",
        f"- Retrieval input: `{args.retrieval.relative_to(ROOT)}`",
        "- API calls: none",
        "",
        "## Prompt sets",
        "",
    ]
    lines.extend(f"- {name}: {count}" for name, count in counts.items())
    lines.extend([
        "",
        "## Output constraints",
        "",
        "- Stage prompts allow only `TA43`, `TA01`, `TA03`, `TA11`, `TN01`.",
        "- Technique prompts allow only `TA43_01`, `TA43_02`, `TA01_01`, `TA01_02`, `TA03_01`, `TA11_01`, `TA11_02`, `TN01_01`.",
        "- RAG prompt sets inject top-5 retrieved snippets.",
        "- The requested result JSON uses `predicted_code`, `confidence`, and one-sentence `reason`.",
    ])
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"built prompts for {len(records)} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

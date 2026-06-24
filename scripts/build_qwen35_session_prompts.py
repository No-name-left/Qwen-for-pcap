#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from build_rag_query import indicator_fields_used as detect_indicator_fields
from qwen35_rag_utils import (
    DEFAULT_RUNTIME_PROFILES,
    REAL_MICRO_DIR,
    ROOT,
    estimate_tokens,
    load_env_file,
    load_json,
    load_runtime_profile,
)


PROMPT_VERSION = "observable_boundary_rag_v3"
TECHNIQUE_CODES = ["TA43_01", "TA43_02", "TA01_01", "TA01_02", "TA03_01", "TA11_01", "TA11_02", "TN01_01"]
CORE_KEYS = [
    "record_id", "session_id", "pcap", "pcap_id", "record_type", "parser_source",
    "start_time", "end_time", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
    "service", "duration", "orig_pkts", "resp_pkts", "orig_bytes", "resp_bytes",
    "conn_state", "history", "same_src_conn_count", "same_src_unique_dst_ports",
    "same_src_unique_dst_ips", "same_src_failed_conn_rate", "same_dst_unique_src_count",
    "same_src_same_dst_port_count", "session_count", "unique_dst_ports", "failed_conn_rate",
    "time_window_neighbor_alert_count", "src_role", "dst_role", "initiator_role", "direction",
    "auth_group_id", "auth_protocol", "attempt_count", "unique_usernames_seen",
    "username_field_seen", "password_field_seen", "failed_login_count",
    "success_after_failures_hint", "repeated_login_attempts", "same_src_same_dst_auth_attempts",
    "time_span", "attempt_rate", "status_code_summary", "ftp_response_codes",
    "ssh_auth_failure_hint", "http_login_paths", "weak_evidence_reason", "evidence_tier",
    "c2_group_id", "connection_count", "interval_summary", "periodicity_score",
    "bytes_pattern", "duration_pattern", "dns_query_repetition", "tls_sni_repetition",
    "beacon_score", "callback_direction_hint", "member_session_count",
]
OBSERVABLE_KEYS = [
    "payload_visibility", "observable_payload_available", "encrypted_protocol",
    "extraction_warnings", "evidence_mapping",
    "http_methods", "http_hosts", "http_uris_sample", "http_full_uri_sample",
    "http_status_codes", "http_user_agents", "http_referrers", "http_content_types",
    "http_request_body_len", "http_response_body_len", "http_cookie_present",
    "http_auth_header_present", "http_multipart_present", "http_upload_hints",
    "request_body_snippets_sanitized", "response_body_snippets_sanitized",
    "suspicious_payload_snippets", "suspicious_http_parameters", "suspicious_uri_patterns",
    "exploit_indicators", "vuln_scan_indicators", "auth_indicators",
    "implant_indicators", "backdoor_access_indicators", "c2_indicators",
    "transferred_files_summary", "dns_summary", "tls_summary", "pcap_summary", "evidence_limits",
]


def load_retrieval(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    data = load_json(path)
    return {item.get("record_id") or item.get("event_id"): item for item in data}


def display_path(path: Path) -> str:
    resolved = path.resolve()
    for base in (ROOT, REAL_MICRO_DIR):
        try:
            return str(resolved.relative_to(base))
        except ValueError:
            continue
    return str(path)


def trim_value(value: Any, char_limit: int, list_limit: int = 12) -> Any:
    if isinstance(value, str):
        return value if len(value) <= char_limit else value[: max(0, char_limit - 15)] + "...[truncated]"
    if isinstance(value, list):
        output = [trim_value(item, max(80, char_limit // max(1, min(len(value), list_limit)))) for item in value[:list_limit]]
        if len(value) > list_limit:
            output.append(f"...[{len(value) - list_limit} more]")
        return output
    if isinstance(value, dict):
        return {str(key): trim_value(item, max(80, char_limit // max(1, len(value)))) for key, item in value.items()}
    return value


def compact_record(record: dict[str, Any], max_chars: int = 4500) -> dict[str, Any]:
    compact = {key: record.get(key) for key in CORE_KEYS if key in record}
    remaining = max(240, max_chars - len(json.dumps(compact, ensure_ascii=False)))
    for key in ("notice_summary", "weird_summary", "alert_summary", "same_pcap_summary", "related_context"):
        if key in record and record.get(key) not in (None, "", [], {}):
            compact[key] = trim_value(record[key], min(900, remaining))
            remaining = max(120, max_chars - len(json.dumps(compact, ensure_ascii=False)))
    if "dst_ports_sample" in record:
        compact["dst_ports_sample"] = trim_value(record["dst_ports_sample"], 400, list_limit=20)
    return compact


def sparse_value(value: Any) -> Any:
    """Omit false/empty indicator members in prompts while keeping full JSON in outputs."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            sparse = sparse_value(item)
            if sparse not in (None, "", [], {}, False):
                out[key] = sparse
        return out
    if isinstance(value, list):
        return [sparse_value(item) for item in value if sparse_value(item) not in (None, "", [], {}, False)]
    return value


def compact_observable(record: dict[str, Any], max_chars: int) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    active_indicators = set(detect_indicator_fields(record))
    for key in OBSERVABLE_KEYS:
        if key not in record or record.get(key) in (None, "", [], {}):
            continue
        if key.endswith("_indicators") and key not in active_indicators:
            continue
        value = sparse_value(record[key]) if key.endswith("_indicators") or key == "transferred_files_summary" else record[key]
        if value in (None, "", [], {}):
            continue
        current = len(json.dumps(compact, ensure_ascii=False))
        remaining = max(100, max_chars - current)
        # PCAP aggregates and limits are deliberately lowest priority and smallest.
        cap = 500 if key == "pcap_summary" else 260 if key == "evidence_limits" else min(850, remaining)
        candidate = trim_value(value, cap, list_limit=5)
        trial = {**compact, key: candidate}
        if len(json.dumps(trial, ensure_ascii=False)) <= max_chars:
            compact[key] = candidate
        elif key in {"payload_visibility", "observable_payload_available", "encrypted_protocol", "extraction_warnings", "suspicious_payload_snippets", "exploit_indicators"}:
            compact[key] = trim_value(value, max(80, remaining), list_limit=3)
    return compact


def instruction_block() -> str:
    return (
        f"PROMPT_VERSION: {PROMPT_VERSION}\n"
        "Classify exactly one PCAP session or behavioral group into the official closed set. Predict technique_code only; stage_code is derived by the program.\n"
        "Return exactly one JSON object and no Markdown, Thinking Process, or text outside JSON.\n"
        "The record is primary evidence. RAG is boundary guidance only; when RAG conflicts with observed behavior, follow the record.\n"
        "Observable indicators are network-side evidence: they may show an attempt, upload, or command text but do not prove host-side execution, persistence, or success.\n"
        "Use only this record and same-PCAP aggregates. Never use IP/domain reputation or context from another PCAP.\n"
        "Missing payload is not proof of normality. Encrypted traffic is not normal by default; judge direction, repetition, timing, fanout, failures, bytes, and endpoint role.\n"
        "If evidence remains insufficient after behavioral review, TN01_01 is allowed. Ordinary HTTP/TLS/DNS or a few normal logins are not attacks.\n"
        "TA43_01 needs port/target fanout or short failed discovery; do not upgrade ordinary port scans to TA43_02. TA43_02 needs service fingerprinting, scanner paths/plugins, CVE or vulnerability-specific probes.\n"
        "TA01_01 needs repeated authentication attempts with failure/credential evidence. TA01_02 needs exploit payload, abnormal URI, injection, traversal, webshell upload, or vulnerability-trigger evidence.\n"
        "For auth_attempt_group, require repeated attempts plus explicit failure or credential-field evidence; weak_auth_evidence is not enough for TA01_01.\n"
        "TA03_01 is deployment/persistence. TA11_01 is attacker-initiated access to an existing backdoor or interactive control entry. TA11_02 is victim-initiated callback/beacon/C2 behavior.\n"
        "For c2_callback_group, use fixed remote endpoint, repeated source-initiated connections, interval/byte patterns, unusual port, and DNS/TLS repetition together.\n"
        "When plaintext suspicious strings are visible, use their URI/body context. When payload_visibility is encrypted_tls or metadata_only, do not invent content and do not default to normal solely because payload is hidden.\n"
        f"Allowed technique_code values: {', '.join(TECHNIQUE_CODES)}. No legacy or invented labels.\n"
        "Required JSON fields: record_id, pcap_id, record_type, start_time, end_time, src_ip, src_port, dst_ip, dst_port, predicted_code, confidence, reason.\n"
        "confidence must be 0..1 and reason must be one short sentence.\n"
    )


def rag_section(snippets: list[dict[str, Any]], profile: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    max_chunks = int(profile.get("max_rag_chunks", 5))
    per_chunk = int(profile.get("max_rag_chars_per_chunk", 550))
    ordered = sorted(snippets, key=lambda item: (not bool(item.get("targeted_boundary")), -float(item.get("score") or 0)))
    selected = ordered[:max_chunks]
    payload = []
    for item in selected:
        payload.append({
            "doc_id": item.get("doc_id"),
            "targeted_boundary": bool(item.get("targeted_boundary")),
            "text": trim_value(str(item.get("text") or ""), per_chunk),
        })
    block = "" if not payload else "RAG_BOUNDARY_AND_TOP_EVIDENCE:\n" + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
    return block, {
        "rag_chunks_included": len(payload),
        "targeted_boundary_doc_ids": [item["doc_id"] for item in payload if item["targeted_boundary"]],
    }


def build_prompt(
    record: dict[str, Any],
    task: str,
    snippets: list[dict[str, Any]] | None,
    profile: dict[str, Any],
    retrieval_meta: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    if task != "technique":
        raise ValueError("only technique classification prompts are supported; stage_code is derived deterministically")
    configured_chars = int(profile.get("max_prompt_chars", 10**9))
    token_chars = int(profile.get("max_prompt_tokens", 3500)) * 3
    max_chars = min(configured_chars, token_chars)
    session_limit = int(profile.get("max_session_context_chars", 4500))
    core = compact_record(record, min(1800, session_limit))
    core_json = json.dumps(core, ensure_ascii=False, separators=(",", ":"))
    observable = compact_observable(record, max(600, session_limit - len(core_json)))
    observable_json = json.dumps(observable, ensure_ascii=False, separators=(",", ":"))
    prefix = instruction_block()
    rag_block, meta = rag_section(snippets or [], profile) if snippets is not None else ("", {"rag_chunks_included": 0, "targeted_boundary_doc_ids": []})
    suffix = "OBSERVABLE_EVIDENCE_FROM_PCAP:\n" + observable_json + "\nCLASSIFICATION_RECORD:\n" + core_json + "\n"
    prompt = prefix + rag_block + suffix
    truncated = "[truncated]" in observable_json or " more]" in observable_json or "[truncated]" in core_json
    if len(prompt) > max_chars and rag_block:
        # Drop lowest-ranked ordinary RAG before any decision-boundary card.
        working = list(snippets or [])
        while len(prompt) > max_chars and any(not item.get("targeted_boundary") for item in working):
            for index in range(len(working) - 1, -1, -1):
                if not working[index].get("targeted_boundary"):
                    working.pop(index)
                    break
            rag_block, meta = rag_section(working, profile)
            prompt = prefix + rag_block + suffix
            truncated = True
    if len(prompt) > max_chars:
        # Preserve schema/instructions and core fields; shorten verbose application summaries.
        available = max(900, max_chars - len(prefix) - len(rag_block) - len("OBSERVABLE_EVIDENCE_FROM_PCAP:\n\nCLASSIFICATION_RECORD:\n\n"))
        core_json = json.dumps(compact_record(record, min(1600, available // 2)), ensure_ascii=False, separators=(",", ":"))
        observable = compact_observable(record, max(450, available - len(core_json)))
        observable_json = json.dumps(observable, ensure_ascii=False, separators=(",", ":"))
        suffix = "OBSERVABLE_EVIDENCE_FROM_PCAP:\n" + observable_json + "\nCLASSIFICATION_RECORD:\n" + core_json + "\n"
        prompt = prefix + rag_block + suffix
        truncated = True
    if len(prompt) > max_chars and rag_block:
        # A pathological record may force all RAG out; the current record always wins.
        rag_block = ""
        meta = {"rag_chunks_included": 0, "targeted_boundary_doc_ids": [], "boundary_dropped_for_core_record": True}
        prompt = prefix + suffix
        truncated = True
    if len(prompt) > max_chars:
        raise ValueError(f"core prompt exceeds profile budget: {len(prompt)} > {max_chars}")
    retrieval_meta = retrieval_meta or {}
    meta.update({
        "prompt_version": PROMPT_VERSION,
        "runtime_profile": profile.get("name", "inline"),
        "prompt_chars": len(prompt),
        "estimated_prompt_tokens": estimate_tokens(prompt),
        "max_prompt_chars": max_chars,
        "budget_truncated": truncated,
        "observable_fields_included": list(observable),
        "indicator_fields_used": retrieval_meta.get("indicator_fields_used") or detect_indicator_fields(record),
        "targeted_rag_triggers": retrieval_meta.get("targeted_rag_triggers", []),
        "targeted_boundary_cards": retrieval_meta.get("targeted_boundary_cards", meta.get("targeted_boundary_doc_ids", [])),
    })
    meta["prompt_budget_summary"] = {
        "prompt_chars": meta["prompt_chars"],
        "estimated_prompt_tokens": meta["estimated_prompt_tokens"],
        "max_prompt_chars": meta["max_prompt_chars"],
        "budget_truncated": meta["budget_truncated"],
        "rag_chunks_included": meta["rag_chunks_included"],
        "observable_chars": len(observable_json),
    }
    return prompt, meta


def prompt_text(
    record: dict[str, Any],
    task: str,
    snippets: list[dict[str, Any]] | None,
    profile: dict[str, Any] | None = None,
) -> str:
    effective = profile or {
        "name": "compat_default", "max_prompt_chars": 11000, "max_rag_chunks": 5,
        "max_rag_chars_per_chunk": 550, "max_session_context_chars": 4500,
    }
    return build_prompt(record, task, snippets, effective)[0]


def write_prompt_set(
    records: list[dict[str, Any]], out_dir: Path, task: str,
    retrieval: dict[str, dict[str, Any]] | None, profile: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    for old_prompt in out_dir.glob("*.txt"):
        old_prompt.unlink()
    manifest = []
    for record in records:
        record_id = record["record_id"]
        retrieval_item = retrieval.get(record_id, {}) if retrieval is not None else {}
        snippets = retrieval_item.get("snippets", []) if retrieval is not None else None
        text, metadata = build_prompt(record, task, snippets, profile, retrieval_item)
        path = out_dir / f"{record_id.replace('/', '_').replace(':', '_')}.txt"
        path.write_text(text, encoding="utf-8")
        manifest.append({"record_id": record_id, "prompt_file": display_path(path), **metadata})
    (out_dir / "prompt_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(manifest), manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build budgeted Qwen session prompts without calling an API.")
    parser.add_argument("--records", type=Path, default=ROOT / "outputs/session_cards/classification_records_all.json")
    parser.add_argument("--retrieval", type=Path, default=ROOT / "outputs/rag_retrieval/qwen35_session_records_retrieved_knowledge_top5.json")
    parser.add_argument("--micro-output-dir", type=Path, default=REAL_MICRO_DIR / "outputs")
    parser.add_argument("--report", type=Path, default=REAL_MICRO_DIR / "outputs/prompts_qwen35_27b_prompt_report.md")
    parser.add_argument("--runtime-profiles", type=Path, default=DEFAULT_RUNTIME_PROFILES)
    parser.add_argument("--runtime-profile", default="ascend_openeuler_qwen35_27b")
    args = parser.parse_args()

    load_env_file(ROOT / ".env")
    load_env_file(ROOT / ".env.local")
    records = load_json(args.records) if args.records.exists() else []
    retrieval = load_retrieval(args.retrieval)
    profile = load_runtime_profile(args.runtime_profile, args.runtime_profiles)
    no_count, no_manifest = write_prompt_set(records, args.micro_output_dir / "prompts_qwen35_27b_technique_no_rag", "technique", None, profile)
    rag_count, rag_manifest = write_prompt_set(records, args.micro_output_dir / "prompts_qwen35_27b_technique_rag", "technique", retrieval, profile)
    all_rows = no_manifest + rag_manifest
    max_chars = max((row["prompt_chars"] for row in all_rows), default=0)
    max_tokens = max((row["estimated_prompt_tokens"] for row in all_rows), default=0)
    targeted = sum(bool(row["targeted_boundary_doc_ids"]) for row in rag_manifest)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Qwen3.5 prompt budget report", "",
        f"- Prompt version: `{PROMPT_VERSION}`", f"- Runtime profile: `{args.runtime_profile}`",
        f"- Records: {len(records)}", f"- No-RAG prompts: {no_count}", f"- RAG prompts: {rag_count}",
        f"- RAG prompts with targeted boundary cards: {targeted}",
        f"- Maximum prompt characters: {max_chars} / {profile.get('max_prompt_chars')}",
        f"- Maximum estimated prompt tokens: {max_tokens} / {profile.get('max_prompt_tokens')}",
        f"- Budget truncations: {sum(bool(row['budget_truncated']) for row in all_rows)}", "",
        "Prompts preserve closed-set definitions and the current record before ordinary RAG. Stage codes are never model-predicted.",
    ]
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"built prompts for {len(records)} records; max_chars={max_chars}; prompt_version={PROMPT_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

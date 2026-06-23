#!/usr/bin/env python3
"""Smoke-test runtime profiles, targeted retrieval, and the Ascend prompt budget."""

from __future__ import annotations

import json

from build_qwen35_session_prompts import PROMPT_VERSION, build_prompt
from build_rag_query import BOUNDARY_DOCS, detect_confusion_groups, record_terms
from qwen35_rag_utils import ROOT, load_runtime_profile
from retrieve_rag import retrieve


def load_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    for name in ("ascend_openeuler_qwen35_27b", "nvidia_ubuntu_online_api", "dry_run_mock"):
        profile = load_runtime_profile(name)
        assert profile["name"] == name
        assert int(profile["max_prompt_chars"]) > 0

    record = {
        "record_id": "budget::scan-web-auth-callback", "pcap_id": "fixture.pcap", "record_type": "scan_group",
        "src_ip": "10.0.0.8", "dst_ip": "10.0.0.9", "service": "https",
        "unique_dst_ports": 181, "failed_conn_rate": 0.88, "same_src_conn_count": 200,
        "http_summary": {"uris": [f"/very/long/scanner/path/{index}?q=" + "x" * 180 for index in range(100)], "note": "Nikto CVE probe command injection webshell"},
        "dns_summary": {"queries": [f"beacon-{index}.example.invalid" for index in range(100)]},
        "tls_summary": {"sni": [f"fixed-{index}.example.invalid" for index in range(100)]},
        "payload_visibility": "plaintext_http",
        "suspicious_payload_snippets": ["q=;exec master..xp_cmdshell 'whoami'"],
        "exploit_indicators": {"command_injection": True, "xp_cmdshell": True, "matched_keywords": ["xp_cmdshell"]},
        "vuln_scan_indicators": {"nikto_user_agent": True, "high_uri_fanout": True, "matched_keywords": ["Nikto"]},
    }
    terms, rules, low_signal = record_terms(record)
    groups = detect_confusion_groups(record)
    assert "ta43_01_vs_ta43_02" in groups
    assert "ta01_02_vs_tn01_01" in groups
    assert "ta11_02_vs_tn01_01" in groups
    query = {
        "record_id": record["record_id"], "query": " ".join(terms), "query_terms": terms,
        "matched_rules": rules, "low_signal": low_signal, "confusion_groups": groups,
        "targeted_boundary_doc_ids": [BOUNDARY_DOCS[group] for group in groups],
    }
    snippets = retrieve([query], load_jsonl(ROOT / "rag/chunks/rag_chunks.jsonl"), top_k=5)[0]["snippets"]
    profile = load_runtime_profile("ascend_openeuler_qwen35_27b")
    prompt, meta = build_prompt(record, "technique", snippets, profile)
    assert len(prompt) <= int(profile["max_prompt_chars"])
    assert meta["estimated_prompt_tokens"] <= int(profile["max_prompt_tokens"])
    assert meta["prompt_version"] == PROMPT_VERSION
    assert meta["targeted_boundary_doc_ids"]
    assert "PROMPT_VERSION: observable_boundary_rag_v3" in prompt
    assert "OBSERVABLE_EVIDENCE_FROM_PCAP:" in prompt
    assert "xp_cmdshell" in prompt
    assert "CLASSIFICATION_RECORD:" in prompt
    print(json.dumps({"prompt_chars": len(prompt), "estimated_tokens": meta["estimated_prompt_tokens"], "boundaries": meta["targeted_boundary_doc_ids"], "truncated": meta["budget_truncated"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

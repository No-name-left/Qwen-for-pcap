#!/usr/bin/env python3
"""Offline regression checks for guarded observable-v3 API evaluation assets."""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path

from build_qwen35_session_prompts import PROMPT_VERSION
from qwen35_rag_utils import DEFAULT_RUNTIME_PROFILES, ROOT, load_runtime_profile
from run_public_eval_api import write_prompts
from run_small_api_eval import select_records


def main() -> int:
    source = ROOT / "datasets/public_eval/strict_observable_v3_records.jsonl"
    records = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    strict = select_records(records, "strict", 9, 3)
    assert len(strict) == 9
    assert Counter(row["technique_code"] for row in strict) == Counter({
        "TA43_01": 3, "TA11_02": 3, "TN01_01": 3,
    })
    pcap = [row for row in strict if row["confidence_level"] == "external_high_pcap"]
    flow = [row for row in strict if row["confidence_level"] == "external_high_flow"]
    assert len(pcap) == 6 and len(flow) == 3
    assert all(
        row["classification_record"].get("pcap_summary") or row["classification_record"].get("c2_group_id")
        for row in pcap
    )
    assert all(not row["classification_record"].get("pcap_summary") for row in flow)

    profile = load_runtime_profile("nvidia_ubuntu_online_api", DEFAULT_RUNTIME_PROFILES)
    with tempfile.TemporaryDirectory(prefix="qwen-small-eval-test-") as tmp:
        out = Path(tmp)
        write_prompts(strict, out, profile)
        no_rag = json.loads((out / "prompts/no_rag/prompt_manifest.json").read_text(encoding="utf-8"))
        rag = json.loads((out / "prompts/rag/prompt_manifest.json").read_text(encoding="utf-8"))
        assert all(not row["targeted_rag_triggers"] and not row["targeted_boundary_cards"] for row in no_rag)
        assert sum(bool(row["observable_fields_included"]) for row in rag) == 9
        # Frozen strict-v3 scan records predate scan-rate summaries; C2 and flow records carry timing.
        assert sum(bool(row["timing_fields_included"]) for row in rag) == 6
        assert sum(bool(row["targeted_boundary_cards"]) for row in rag) >= 6
        assert any(row["targeted_rag_triggers"] for row in rag)
        prompt_blob = "\n".join(path.read_text(encoding="utf-8") for path in (out / "prompts").rglob("*.txt")).lower()
        assert prompt_blob.count(f"prompt_version: {PROMPT_VERSION.lower()}") == 18
        assert prompt_blob.count("observable_evidence_from_pcap:") == 18
        assert not any(token in prompt_blob for token in ("xp_cmdshell", "powershell", "/bin/sh", "union select"))
    print("small API eval selection, observable evidence, targeted RAG, and prompt safety passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

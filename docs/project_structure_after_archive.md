# Project Structure After Non-mainline Archive

Generated at: 2026-06-10T18:27:02

## Current Mainline Structure

```text
PCAP
-> tshark / Zeek / Suricata parsing
-> sessionization / session card
-> deterministic RAG query builder
-> RAG retriever
-> Qwen3.5-27B session-level classification
-> stage / technique code prediction
-> competition CSV submission
-> human-readable analysis report
```

## Archived Content Overview

- Dry-run candidates before apply: 173
- Actually moved files: 172
- Uncertain candidates left in place: 1
- `legacy_event_card_pipeline`: 30
- `legacy_qwen14b`: 19
- `old_prompts`: 52
- `old_reports`: 11
- `old_scripts`: 9
- `partial_runs`: 51

## Mainline Must-exist Check

- `rag/knowledge`: exists
- `rag/chunks/rag_chunks.jsonl`: exists
- `rag/index/keyword_index.json`: exists
- `rag/metadata/source_manifest.csv`: exists
- `rag/metadata/rag_manifest.csv`: exists
- `configs/competition_label_schema.yaml`: exists
- `configs/llm_qwen35_27b.yaml`: exists
- `docs/current_task_definition.md`: exists
- `docs/project_paths.md`: exists
- `outputs/session_cards`: missing / not generated yet
- `outputs/submissions`: missing / not generated yet
- `scripts/build_session_cards.py`: missing / not generated yet
- `scripts/build_qwen35_session_test_set.py`: missing / not generated yet
- `scripts/build_qwen35_session_prompts.py`: missing / not generated yet
- `scripts/export_competition_csv.py`: missing / not generated yet

## Remaining Suspected Legacy Files

- `scripts/run_qwen_openai_compatible_isolated.py`

## Micro-test Directory Naming

- Detected test-like top-level dirs: `微型test_v1`, `微型test_v2`
- `微型test_v1` still exists as a legacy/raw-PCAP container because raw PCAP files were not moved.
- No `微型testv2` directory was detected; only the underscored v2 spelling `微型test_v2` exists. Keep this spelling for future work.

## Recommendation

Keep current mainline files in place and implement missing session-card, prompt, and CSV exporter scripts before formal runs.

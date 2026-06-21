# RAG Next Steps

These next steps follow the current competition task definition: session-level classification into official stage / technique codes, followed by CSV export. They replace the older event-level JSON testing plan.

## 1. Session Card Builder

Build session cards from `outputs/parsed/` without AI. Sessionization should use:

- five-tuple grouping;
- source/destination port changes;
- Zeek `conn.uid`;
- tshark `tcp.stream`;
- UDP five-tuple plus time window;
- per-PCAP boundaries only, with no cross-PCAP inference.

Recommended outputs:

```text
outputs/session_cards/session_cards_all.json
outputs/session_cards/llm_session_cards_all.json
```

## 2. Deterministic RAG Query Builder

Input a session card and build `rag_query` without AI. Use protocols, ports, Zeek fields, tshark stream statistics, DNS names, HTTP fields, TLS SNI, and compact behavior summaries. Do not read evaluation files or expected labels.

Recommended output:

```text
outputs/rag_queries/
```

## 3. Chunk Builder

Read `rag/knowledge/**/*.md`, preserve front matter metadata, and split by heading and paragraph into stable chunks. Output:

```text
rag/chunks/rag_chunks.jsonl
```

## 4. Keyword Index Builder

Build `keyword_index.json` from document metadata, keywords, title, headings, and body terms. Keep exact signature, protocol, port, and tool-field terms as strong keys. Output:

```text
rag/index/keyword_index.json
```

## 5. Retriever

Use keyword strong recall plus metadata weighting as the baseline. Return top-k snippets per session. Optional vector / hybrid retrieval can be added later, but it is not a required dependency.

Recommended output:

```text
outputs/rag_retrieval/
```

## 6. Technique Prompt Builders

Generate RAG and no-RAG technique prompt sets for:

```text
微型test_v2/outputs/prompts_qwen35_27b_technique_no_rag/
微型test_v2/outputs/prompts_qwen35_27b_technique_rag/
```

Prompt output requests one official `technique_code`. It must not request `stage_code`; the exporter derives stage deterministically.

## 7. Qwen3.5-27B Runner

Use `configs/llm_qwen35_27b.yaml` and environment variables:

```bash
export BASE_URL="http://127.0.0.1:8000/v1"
export API_KEY="EMPTY"
export MODEL="qwen3.5"
```

The `LLM_*` aliases remain supported. Never write real tokens into code, prompts, configs, reports, or logs.

## 8. CSV Exporter

Export final competition files:

```text
outputs/submissions/stage1_submission.csv
outputs/submissions/stage2_submission.csv
outputs/submissions/submission_export_report.md
```

Use official templates if provided. Keep reasons in a human-readable report or optional audit file; do not add non-template columns to the final submission unless allowed.

## 9. Validation and Reporting

When no official session-level labels are available, report only rough agreement, qualitative comparison, or local validation. Do not report strict accuracy. When official labels are available, focus on macro-F1 / per-class F1 rather than overall accuracy or normal-class dominance.

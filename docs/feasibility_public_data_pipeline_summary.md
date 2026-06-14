# Feasibility public data pipeline summary

## Verdict

`FEASIBILITY_DATA_PARTIAL_BUT_USABLE`

The offline feasibility pipeline is non-empty and usable for smoke testing. It is still partial because no reliable Nmap/port-scan PCAP exists in the current tree, so no `scan_group` was produced.

## Data Used

- CTU-13 Scenario 1 PCAP symlink: `datasets/public/feasibility/raw/ctu13_scenario1_botnet.pcap`.
- CTU-13 bidirectional labels symlink: `datasets/public/feasibility/labels/ctu13_scenario1_capture20110810.binetflow`.
- CSE-CIC-IDS2018 flow-only CSV symlinks for brute force, web attack, bot, and infiltration under `datasets/public/feasibility/labels/`.

CTU-13 is suitable for PCAP parser testing. CSE-CIC-IDS2018 selected CSV files are flow-label evaluation/manual-review assets only and cannot test the PCAP parser.

## Pipeline Counts

- Parsed PCAP files: 1.
- Session cards: 200.
- Scan groups: 0.
- Classification records: 200.
- RAG queries: 200.
- RAG retrieval results: 200.
- Stage no-RAG prompts: 200.
- Stage RAG prompts: 200.
- Technique no-RAG prompts: 200.
- Technique RAG prompts: 200.
- Stage dry-run CSV rows: 200.
- Technique dry-run CSV rows: 200.

## Coverage

- `TA43_01`: not covered by a reliable local Nmap/port-scan PCAP; `scan_group` count is 0.
- `TA43_02`: still missing reliable public sample.
- `TA01_01`: available through CSE-CIC-IDS2018 brute-force flow CSV only.
- `TA01_02`: available through CSE-CIC-IDS2018 web-attack flow CSV only, medium confidence.
- `TA03_01`: still missing reliable sample; infiltration is manual review only.
- `TA11_01`: still missing reliable sample; infiltration is manual review only.
- `TA11_02`: available for public-label evaluation through CTU-13 and CSE Bot data. Prompt records do not include public labels as answers.
- `TN01_01`: available through CSE benign rows and CTU normal/background labels for evaluation planning.

## Parse Notes

- `tshark` succeeded on the CTU-13 PCAP.
- Suricata ran and produced `eve.json`, but no alerts matched the default enabled rules.
- Zeek is unavailable in this environment; session cards were generated through the tshark packet aggregation fallback.

## Outputs

- `outputs/session_cards/feasibility/session_cards_all.json`
- `outputs/session_cards/feasibility/scan_groups.json`
- `outputs/session_cards/feasibility/classification_records_all.json`
- `outputs/rag_queries/feasibility/qwen35_session_records_rag_queries.jsonl`
- `outputs/rag_retrieval/feasibility/qwen35_session_records_retrieved_knowledge_top5.json`
- `微型test_v2/outputs/feasibility/prompts_qwen35_27b_stage_no_rag/`
- `微型test_v2/outputs/feasibility/prompts_qwen35_27b_stage_rag/`
- `微型test_v2/outputs/feasibility/prompts_qwen35_27b_technique_no_rag/`
- `微型test_v2/outputs/feasibility/prompts_qwen35_27b_technique_rag/`
- `outputs/submissions/feasibility/stage1_submission_dry_run.csv`
- `outputs/submissions/feasibility/stage2_submission_dry_run.csv`

The dry-run CSV files are placeholders using fallback normal codes; they are not model predictions.

## Recommendation

This is suitable for a small Qwen3.5-27B API smoke test of prompt formatting and end-to-end plumbing after explicit approval. It is not yet suitable for balanced official-code performance testing or SFT preparation because `TA43_01`, `TA43_02`, `TA03_01`, and `TA11_01` still need reliable samples.

## Safety

- Online LLM/API called: no.
- API quota used: no.
- Tokens written: no.
- Public labels added to RAG main knowledge: no.
- Large PCAP/CSV files are ignored by Git policy.

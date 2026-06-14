# Current online model status

This note records online model status only. It does not contain tokens, API keys, or private credentials.

## Mainline model

- Current mainline model target: `Qwen3.5-27B`.
- Existing config: `configs/llm_qwen35_27b.yaml`.
- Future online calls must use session-level prompts and official competition codes, not legacy event-level `attack_type` / `attack_stage` outputs.

## Previously observed online status

- Hugging Face Router connectivity was previously verified for `Qwen/Qwen3.5-27B:novita`.
- A legacy event-level online test did not finish because the provider returned `402 monthly included credits depleted`.
- Legacy no-RAG coverage was only `6/37` events and legacy RAG coverage was `0/37` events. Those runs are not formal conclusions for the competition mainline.

## Required next online test shape

- Use session cards or scan-group classification records as the unit of judgment.
- Restrict stage predictions to `TA43`, `TA01`, `TA03`, `TA11`, `TN01`.
- Restrict technique predictions to `TA43_01`, `TA43_02`, `TA01_01`, `TA01_02`, `TA03_01`, `TA11_01`, `TA11_02`, `TN01_01`.
- Do not use expected labels, answer sheets, raw test answers, IP reputation, or domain reputation.
- Do not share context across PCAP files.
- Do not write any token into docs, prompts, configs, reports, or RAG knowledge.

# Project cleanup inventory

- Inventory date: 2026-06-15
- Baseline commit before cleanup: `da4273e Complete official-code data RAG coverage and small evaluation`
- Tracked working tree before cleanup: clean.
- Ignored local data before cleanup: present, including `.env`, public raw datasets, PCAPs, prompt directories, API outputs, Zeek/Suricata logs, and parsed/session-card outputs.

## Recent commits

```text
da4273e Complete official-code data RAG coverage and small evaluation
d5e2a97 Run Zeek-based large-scale Qwen-for-pcap evaluation
e7f1aab Run final medium-scale Qwen3.5 technique RAG evaluation
ac862ef Run medium-scale technique RAG test with API enabled
1ae8ea0 Run medium-scale Qwen3.5 RAG feasibility evaluation
```

## Main tracked documentation before cleanup

Mainline docs:

- `docs/current_task_definition.md`
- `docs/data_versioning_policy.md`
- `docs/final_zeek_based_large_scale_test_summary.md`
- `docs/official_code_data_rag_sft_small_test_summary.md`
- `docs/project_paths.md`
- `docs/session_level_mainline_implementation_summary.md`
- `docs/sft_candidate_review_report.md`
- `docs/sft_data_readiness_report.md`
- `docs/targeted_patch_after_zeek_eval.md`
- `docs/toolchain_status_report.md`
- `docs/deployment/*.md`

Historical docs found before cleanup:

- `docs/git_commit_summary_*.md`
- `docs/medium_scale_*.md`
- `docs/mixed_small_*.md`
- `docs/feasibility_public_data_pipeline_summary.md`
- `docs/portscan_feasibility_gap_fix_summary.md`
- older project migration/release/status notes.

## RAG inventory

Mainline RAG content:

- `rag/knowledge/competition_labels/`
- 8 official-code docs: `TA43_01`, `TA43_02`, `TA01_01`, `TA01_02`, `TA03_01`, `TA11_01`, `TA11_02`, `TN01_01`
- 5 required boundary docs:
  - `boundary_TA43_01_vs_TA43_02.md`
  - `boundary_TA43_02_vs_TA01_02.md`
  - `boundary_TA01_01_vs_TN01_01.md`
  - `boundary_TA11_02_vs_TN01_01.md`
  - `boundary_TA03_01_vs_TA11_01_vs_TA11_02.md`
- `rag/chunks/rag_chunks.jsonl`
- `rag/index/keyword_index.json`
- latest reports under `rag/reports/official_code_rag_*`

Historical RAG reports were present and are archived under `rag/reports/archive/`.

## Dataset metadata inventory

Mainline metadata:

- `datasets/metadata/official_code_data_coverage_audit.*`
- `datasets/metadata/official_code_data_supplement_report.*`
- `datasets/metadata/public_label_mapping_policy.*`
- `datasets/metadata/current_official_code_coverage_matrix.*`
- `datasets/metadata/current_dataset_inventory.*`
- `datasets/metadata/public_dataset_manifest.*`

Historical supplement/search/feasibility reports are archived under `datasets/metadata/archive/`.

## Outputs overview

Mainline tracked outputs retained:

- `outputs/README.md`
- `outputs/eval_sets/official_code_balanced_eval_set.*`
- `outputs/eval_sets/small_coverage_test_set.*`
- `outputs/tool_checks/*`
- `outputs/zeek_rebuild/zeek_rebuild_summary.*`
- `outputs/zeek_rebuild/zeek_vs_tshark_fallback_comparison.*`
- `outputs/zeek_rebuild/*_report.md` lightweight reports

Historical tracked API-test reports were moved to `docs/archive/outputs_api_tests/`.

Ignored local outputs retained but not committed:

- prompt directories under `outputs/api_tests/**/prompts*`
- API raw and parsed outputs under `outputs/api_tests/**/raw` and `outputs/api_tests/**/parsed`
- local CSV submissions under `outputs/**/submissions/*.csv`
- full parsed/session-card/Zeek/Suricata outputs
- release tarballs and local caches

## Mainline versus history

Mainline:

- Zeek-first PCAP parsing and session records.
- Suricata evidence and tshark fallback support.
- scan_group handling for portscan.
- official-code RAG, official technique prediction, deterministic stage fallback, CSV export.

Historical experiments:

- mixed-small API runs.
- medium-scale API readiness/rerun/fallback reports.
- old prompt/RAG patch process reports.
- old feasibility/nmap search and supplement attempts.

Local ignored data:

- raw datasets and PCAPs.
- generated Zeek/Suricata logs.
- API prompt/raw/parsed outputs.
- local `.env`.

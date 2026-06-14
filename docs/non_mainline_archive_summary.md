# Non-mainline Archive Summary

Generated at: 2026-06-10T18:27:02

1. Dry-run candidate count: 173
2. Actual archived file count: 172
3. Counts by archive subdirectory:
   - `legacy_qwen14b`: 19
   - `legacy_qwen35_event_level`: 0
   - `legacy_event_card_pipeline`: 30
   - `old_prompts`: 52
   - `partial_runs`: 51
   - `old_reports`: 11
   - `old_docs`: 0
   - `old_scripts`: 9
   - `uncertain_need_review`: 0
4. Mainline files complete: yes
5. Uncertain files requiring manual review: 1
6. Potential path-reference risks: 32
7. Micro-test directory mix: `微型test_v1` and `微型test_v2` exist; no `微型testv2` directory was detected. Keep `微型test_v2` for future v2 work.

## Reference Risk Notes

- `configs/attack_taxonomy.yaml` referenced by: README.md, docs/project_context_migration_scan_report.md, docs/project_paths.md, docs/task_context_update_summary.md, scripts/archive_non_mainline_files.py
- `outputs/archive/legacy_qwen14b_20260610_080338/archive_manifest.md` referenced by: scripts/archive_non_mainline_files.py
- `outputs/archive/legacy_qwen14b_20260610_080338/微型test_v2/outputs/llm_results/qwen3_14b_test_result.json` referenced by: scripts/archive_non_mainline_files.py
- `outputs/evaluation/llm_event_id_map.json` referenced by: scripts/archive_non_mainline_files.py, scripts/build_event_cards.py
- `outputs/evaluation/llm_event_label_map.json` referenced by: scripts/archive_non_mainline_files.py, scripts/build_event_cards.py
- `outputs/evaluation/public_event_labels.json` referenced by: scripts/archive_non_mainline_files.py, scripts/build_event_cards.py
- `outputs/event_cards/llm_event_cards_all.json` referenced by: scripts/archive_non_mainline_files.py, scripts/build_event_cards.py
- `outputs/event_cards/public_event_cards_v2.json` referenced by: scripts/build_event_cards.py
- `outputs/event_cards/public_event_cards_v2_report.md` referenced by: scripts/build_event_cards.py
- `rag/reports/qwen35_27b_rag_retrieval_test_report.md` referenced by: scripts/test_rag_retrieval.py
- `rag/reports/qwen35_27b_rag_retrieval_test_results.json` referenced by: scripts/test_rag_retrieval.py
- `rag/reports/rag_library_report.md` referenced by: scripts/build_rag_library_initial.py
- `rag/reports/rag_quality_audit_report.md` referenced by: scripts/audit_rag_library_quality.py
- `schemas/event_card.schema.json` referenced by: docs/project_context_migration_scan_report.md, docs/task_context_update_summary.md, scripts/archive_non_mainline_files.py
- `schemas/llm_output.schema.json` referenced by: docs/project_context_migration_scan_report.md, docs/task_context_update_summary.md, scripts/archive_non_mainline_files.py
- `scripts/build_event_cards.py` referenced by: README.md, docs/project_context_migration_scan_report.md, docs/task_context_update_summary.md, scripts/archive_non_mainline_files.py
- `scripts/build_qwen35_27b_no_rag_prompt.py` referenced by: docs/project_context_migration_scan_report.md, scripts/archive_non_mainline_files.py
- `scripts/build_rag_augmented_prompt.py` referenced by: docs/project_context_migration_scan_report.md, scripts/archive_non_mainline_files.py
- `scripts/compare_rag_vs_no_rag.py` referenced by: scripts/archive_non_mainline_files.py
- `微型test_v1/outputs/batch_packets/sample.csv` referenced by: scripts/audit_rag_library_quality.py, scripts/build_event_cards.py, scripts/build_qwen35_27b_no_rag_prompt.py, scripts/build_rag_library_initial.py, scripts/build_rag_query.py, scripts/final_rag_review_patch.py, scripts/patch_rag_stable_sources_readme.py
- `微型test_v1/outputs/packets.csv` referenced by: scripts/build_event_cards.py, scripts/build_parse_summary.py, scripts/build_rag_library_initial.py, scripts/parse_public_pcaps.py
- `微型test_v1/pcaps/nmap_captures_2/README.txt` referenced by: docs/project_context_migration_scan_report.md, docs/task_context_update_summary.md, scripts/archive_non_mainline_files.py, scripts/build_rag_library_initial.py, scripts/ground_rag_sources.py, scripts/patch_rag_stable_sources_readme.py
- `微型test_v1/README.md` referenced by: docs/project_context_migration_scan_report.md, docs/task_context_update_summary.md, scripts/archive_non_mainline_files.py, scripts/build_rag_library_initial.py, scripts/ground_rag_sources.py, scripts/patch_rag_stable_sources_readme.py
- `微型test_v2/outputs/event_cards/qwen_test_event_cards.json` referenced by: scripts/build_qwen35_27b_no_rag_prompt.py, scripts/build_rag_augmented_prompt.py, scripts/build_rag_query.py, scripts/retrieve_rag.py
- `微型test_v2/outputs/llm_results_qwen35_27b_no_rag/qwen35_27b_no_rag_result.json` referenced by: scripts/archive_non_mainline_files.py, scripts/compare_rag_vs_no_rag.py
- `微型test_v2/outputs/prompts_qwen35_27b_no_rag/qwen35_27b_no_rag_prompt_report.md` referenced by: scripts/build_qwen35_27b_no_rag_prompt.py
- `微型test_v2/outputs/prompts_qwen35_27b_no_rag_b2/qwen35_27b_no_rag_prompt_report.md` referenced by: scripts/build_qwen35_27b_no_rag_prompt.py
- `微型test_v2/outputs/prompts_qwen35_27b_rag/qwen35_27b_rag_prompt_report.md` referenced by: scripts/build_rag_augmented_prompt.py
- `微型test_v2/outputs/prompts_qwen35_27b_rag_b2/qwen35_27b_rag_prompt_report.md` referenced by: scripts/build_rag_augmented_prompt.py
- `微型test_v2/outputs/rag_eval_qwen35_27b/rag_ablation_comparison.md` referenced by: scripts/archive_non_mainline_files.py, scripts/compare_rag_vs_no_rag.py
- `微型test_v2/outputs/rag_eval_qwen35_27b/rag_changed_predictions.json` referenced by: scripts/compare_rag_vs_no_rag.py
- `微型test_v2/outputs/rag_eval_qwen35_27b/rag_eval_summary.json` referenced by: scripts/compare_rag_vs_no_rag.py

## Next Steps

- Review `archive_manifest.md` for moved files with reference risk.
- Implement or confirm session-card generation and competition CSV export scripts.
- Keep legacy artifacts in `_non_mainline_archive/` unless a specific file is needed for migration.

## Clear Verdict

`NON_MAINLINE_ARCHIVE_COMPLETED`

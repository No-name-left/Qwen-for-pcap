# Project archive manifest

## Archive locations

- `docs/archive/commit_summaries/`
- `docs/archive/legacy_api_tests/`
- `docs/archive/legacy_data_pipeline/`
- `docs/archive/legacy_project_notes/`
- `docs/archive/outputs_api_tests/`
- `docs/archive/outputs_eval_sets/`
- `docs/archive/outputs_misc/`
- `rag/reports/archive/`
- `datasets/metadata/archive/`

## Archived documentation

Moved to `docs/archive/commit_summaries/`:

- old `docs/git_commit_summary_*.md` files through the official-code small-test commit.

Moved to `docs/archive/legacy_api_tests/`:

- old medium-scale readiness/rerun/final API summaries.
- old mixed-small API summaries.

Moved to `docs/archive/legacy_data_pipeline/`:

- old feasibility public-data pipeline summary.
- old portscan feasibility gap summary.

Moved to `docs/archive/legacy_project_notes/`:

- old online model status.
- old context migration and project-structure notes.
- old release package and Zeek patch process notes.

## Archived RAG reports

Moved to `rag/reports/archive/`:

- old RAG update report.
- old online quota/next-step note.
- old Qwen3.5 RAG retrieval test report/results.
- old RAG fact-check/source-grounding/final-coverage reports.
- old targeted RAG prompt patch report.

These are replaced for mainline reading by:

- `rag/reports/official_code_rag_coverage_audit.*`
- `rag/reports/official_code_rag_rebuild_report.*`
- `rag/reports/official_code_rag_retrieval_test.*`

## Archived dataset metadata

Moved to `datasets/metadata/archive/`:

- old supplement attempt report.
- old nmap scan inventory.
- old portscan data search report.
- old public feasibility test plan.

These are replaced for mainline reading by:

- `datasets/metadata/official_code_data_coverage_audit.*`
- `datasets/metadata/official_code_data_supplement_report.*`
- `datasets/metadata/current_official_code_coverage_matrix.*`

## Archived output reports

Moved to `docs/archive/outputs_api_tests/`:

- tracked medium-scale API run reports, prechecks, eval reports, merge reports, and submission reports.
- tracked mixed-small failure/rerun/submission reports.
- tracked Zeek-eval API/evaluation/error/prompt/submission reports.
- tracked Zeek-eval patch-test reports.

Moved to `docs/archive/outputs_eval_sets/`:

- the earlier unbalanced `official_code_eval_set.*`.

Moved to `docs/archive/outputs_misc/`:

- old supplemented parse summaries.

## Retained in place because of uncertainty or mainline relevance

- `outputs/api_tests/medium_scale/selected_records.json`
- `outputs/api_tests/medium_scale/public_reference_labels.json`
- `outputs/api_tests/medium_scale/stage_from_technique*_results.json`
- `outputs/api_tests/mixed_small/failed_*_records.json`
- `outputs/tool_checks/*`
- `outputs/zeek_rebuild/*`
- `outputs/eval_sets/official_code_balanced_eval_set.*`
- `outputs/eval_sets/small_coverage_test_set.*`

These files are either useful as exact test crosswalks, detailed local diagnostic artifacts, or current mainline metadata. They were not deleted.

## Replaced historical conclusions

- medium-scale and mixed-small API conclusions are superseded by the latest small coverage summary.
- old RAG coverage/readiness conclusions are superseded by the official-code RAG coverage/rebuild/retrieval reports.
- old feasibility data search reports are superseded by the official-code data coverage audit.
- old process commit summaries are superseded by the mainline manifest and cleanup summary.

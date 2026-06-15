# Outputs cleanup report

## Tracked outputs before cleanup

Tracked outputs included:

- current eval metadata under `outputs/eval_sets/`
- Zeek rebuild summaries and lightweight reports under `outputs/zeek_rebuild/`
- toolchain checks under `outputs/tool_checks/`
- historical medium-scale, mixed-small, Zeek-eval, and patch-test API reports
- older unbalanced eval-set metadata
- some retained result/crosswalk files used for manual comparison

## Retained

Current mainline retained in `outputs/`:

- `outputs/README.md`
- `outputs/eval_sets/official_code_balanced_eval_set.*`
- `outputs/eval_sets/small_coverage_test_set.*`
- `outputs/tool_checks/*`
- `outputs/zeek_rebuild/zeek_rebuild_summary.*`
- `outputs/zeek_rebuild/zeek_vs_tshark_fallback_comparison.*`
- `outputs/zeek_rebuild/classification_records/classification_records_report.md`
- `outputs/zeek_rebuild/session_cards/session_cards_report.md`

Retained because they may still be needed for exact manual crosswalk/debugging:

- `outputs/api_tests/medium_scale/selected_records.json`
- `outputs/api_tests/medium_scale/selected_record_ids.txt`
- `outputs/api_tests/medium_scale/public_reference_labels.json`
- `outputs/api_tests/medium_scale/stage_from_technique_results.json`
- `outputs/api_tests/medium_scale/stage_from_technique_rerun_results.json`
- `outputs/api_tests/mixed_small/failed_stage_records.json`
- `outputs/api_tests/mixed_small/failed_technique_records.json`

## Archived

Moved to `docs/archive/outputs_api_tests/`:

- medium-scale API prechecks, run reports, eval reports, merge reports, and submission reports.
- mixed-small failure/rerun/submission reports.
- Zeek-eval API/eval/error/prompt/submission reports.
- Zeek-eval patch-test reports.

Moved to `docs/archive/outputs_eval_sets/`:

- earlier unbalanced `official_code_eval_set.*`.

Moved to `docs/archive/outputs_misc/`:

- old supplemented parse summaries.

## Ignored local outputs still present

The following categories remain local and ignored:

- `outputs/api_tests/**/prompts*`
- `outputs/api_tests/**/raw`
- `outputs/api_tests/**/parsed`
- `outputs/api_tests/small_coverage/` detailed small-test local artifacts
- generated CSV submissions under `outputs/**/submissions/*.csv`
- full parsed data under `outputs/parsed/`
- full session cards under `outputs/session_cards/`
- Zeek logs under `outputs/zeek_logs/`
- Suricata logs under `outputs/suricata_logs/`
- release tarballs under `outputs/release/`

No ignored raw datasets or original PCAPs were deleted.

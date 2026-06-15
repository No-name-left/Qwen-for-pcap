# Project cleanup summary

- Clear verdict: `PROJECT_CLEANUP_COMPLETE_MAINLINE_READY`
- Cleanup date: 2026-06-15
- Scope: documentation, metadata organization, archive manifests, README, status handoff, and `.gitignore` safety.

## Cleanup goal

Organize Qwen-for-pcap after multiple API tests, data preparation passes, RAG patches, and reports. The cleanup keeps the Zeek-first official-code mainline visible while preserving historical reports in archives.

## Mainline retained

- Core scripts, configs, READMEs, and shell entry points.
- Official-code RAG docs, boundary docs, chunks, index, and latest RAG reports.
- Official-code data coverage and supplement metadata.
- Balanced eval and small coverage eval metadata.
- SFT candidate audit/review/plan metadata.
- Zeek rebuild summaries and toolchain reports.
- Deployment docs under `docs/deployment/`.

## Archived

- Old commit summaries.
- Old mixed-small and medium-scale API summary docs.
- Old RAG intermediate reports.
- Old feasibility/search/supplement metadata.
- Old tracked output test reports.
- Earlier unbalanced eval-set metadata.

See `docs/project_archive_manifest.md` for paths and rationale.

## Deleted

No tracked files were deleted. Files were moved with `git mv` into archive locations.

Ignored untracked raw data and generated outputs were not deleted.

## Ignored local large/sensitive categories retained

- `.env`
- PCAP/cap/pcapng and raw public datasets
- binetflow/raw downloaded labels
- prompt directories
- API raw and parsed outputs
- generated local CSV submissions
- Zeek/Suricata logs
- release tarballs and caches

## How to read the project now

1. Start with `README.md`.
2. Read `docs/current_project_status_for_assistant.md`.
3. Use `docs/project_mainline_manifest.md` for file navigation.
4. Use `docs/official_code_data_rag_sft_small_test_summary.md` for current model/data conclusion.
5. Use `docs/project_archive_manifest.md` only when historical context is needed.

## Next recommendations

1. Do a record-by-record audit of the 20 small coverage errors.
2. Improve prompt/RAG/evidence summaries for flow-only and callback cases.
3. Re-run the same 20-record small test.
4. Only then consider expanding to 50-100 records.
5. Keep SFT on hold until missing classes and medium candidates are reviewed.

## Risks

- Three official codes still lack reliable local samples.
- Flow-only labels are not PCAP parser validation.
- Historical tracked result/crosswalk files remain for manual reference and should not be treated as current benchmark truth.
- API outputs and prompt directories remain local ignored artifacts.

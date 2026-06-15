# Qwen3.5-27B online quota and next step summary

This report is a quota and execution-status note. It is not RAG knowledge and must not be indexed as part of `rag/knowledge/`.

## Status

- Mainline model target: `Qwen3.5-27B`.
- Previously validated provider/model route: `Qwen/Qwen3.5-27B:novita` through Hugging Face Router.
- Legacy event-level testing was interrupted by `402 monthly included credits depleted`.
- Legacy no-RAG `6/37` and RAG `0/37` event-level results are incomplete, legacy-only observations and cannot support formal competition conclusions.

## Next step

Run only after the offline session-level pipeline is ready:

1. Build session cards and scan-group classification records.
2. Retrieve official-code RAG snippets by `record_id`.
3. Generate official-code stage and technique prompts.
4. Use the OpenAI-compatible runner only with explicit user approval and configured environment variables.

No token or API key is stored in this report.

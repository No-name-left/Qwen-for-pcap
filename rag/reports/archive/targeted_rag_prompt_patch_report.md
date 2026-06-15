# Targeted RAG/prompt patch report

- Added RAG boundary doc: `rag/knowledge/competition_labels/conservative_normal_vs_callback_boundary.md`.
- Rebuilt RAG chunks and keyword index.
- Prompt now explicitly distinguishes conservative normal policy from overusing TN01_01.
- Flow-only rows remain secondary and are not evidence of parser correctness.
- API patch test was not run because the HF Router smoke run stalled.

# Public dataset usage

## Reproducible workflow

```bash
python3 scripts/download_public_datasets.py --dry-run --profile coverage
python3 scripts/download_public_datasets.py --profile coverage --max-gb 1
python3 scripts/prepare_public_eval_records.py
python3 scripts/build_public_eval_split.py
python3 scripts/run_public_eval_api.py
```

The final command is dry-run by default: it generates paired `technique_no_rag` and `technique_rag` prompts but makes no API call. Add `--run-api` only after configuring `BASE_URL`, `MODEL`, and `API_KEY`, or their `LLM_*` aliases.

## Provenance rules

- PCAP records should follow Zeek first, with TShark as the fallback/auxiliary parser, before session-card or scan-group construction.
- `flow_csv` sources are normalized as `record_type=flow_only`. They are never described as PCAP sessions and are reported separately.
- High-confidence evaluation uses only close label mappings. Medium/low records are retained for exploratory boundary testing.
- Ground-truth fields live outside `classification_record`; prompt generation receives evidence fields only.
- `technique_code` is the only model label. `stage_code` is derived deterministically by the existing exporter.

## Data safety

- The downloader allowlist contains only network traces, labels, README files, and official source pages.
- Full collections over 10GB remain skipped unless explicitly opted in with both `--allow-large` and a sufficient budget.
- Malware sample archives and executables are forbidden. Malware-Traffic-Analysis.net and Stratosphere MCF selections are PCAP-only and manually reviewed.
- Raw PCAP and flow CSV files remain ignored by Git; manifests, hashes, label policies, and small evaluation records are trackable.

## Evaluation interpretation

Use four views in `summary.md`: high-confidence only, all mapped labels, flow-only, and PCAP/session-derived. Accuracy changes between RAG and no-RAG are meaningful only within the same paired record set and confidence tier.

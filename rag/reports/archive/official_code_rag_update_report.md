# Official code RAG update report

## Summary

- Added official-code knowledge directory: `rag/knowledge/competition_labels/`.
- Added documents: 9.
- Updated manifest: `rag/metadata/rag_manifest.csv`.
- Rebuilt chunks: `rag/chunks/rag_chunks.jsonl`.
- Rebuilt keyword index: `rag/index/keyword_index.json`.
- RAG quality check: `python3 scripts/test_rag_retrieval.py` passed `15/15`.

## Added official-code documents

- `phase_codes.md`
- `technique_codes.md`
- `port_scan_vs_vulnerability_scan.md`
- `vulnerability_scan_vs_exploitation.md`
- `bruteforce_boundary.md`
- `backdoor_implant_access_callback_boundary.md`
- `session_and_scan_group_policy.md`
- `anonymized_ip_domain_policy.md`
- `normal_business_traffic_boundary.md`

## Safety checks

- The new documents contain no expected labels, raw test answers, token values, or answer-sheet material.
- The documents explicitly avoid IP/domain reputation.
- Multi-port port scanning is documented as a `scan_group` policy.
- Deployment notes were not added under `rag/knowledge/` and are not part of the RAG main knowledge base.

## Rebuild result

- Source knowledge documents: 80.
- Generated chunks: 83.
- Keyword index tokens: 1408.

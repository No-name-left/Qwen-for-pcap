# RAG Indexes

This directory stores retrieval indexes for the session-level RAG baseline.

Current expected output:

- `keyword_index.json`: deterministic keyword index over titles, metadata, headings, and body terms.
- Optional future vector or hybrid indexes when the environment supports them.
- Metadata sidecars may filter by source category, official code family, protocol, port, signature, tool field, and false-positive topic.

The current baseline is keyword + metadata retrieval. Vector / hybrid retrieval can improve fuzzy recall later, but it is not a required dependency for the competition pipeline.

Index safety constraints:

- Do not index test answers, expected labels, MTA answers PDF concrete answers, raw private PCAP paths, tokens, or credentials.
- Do not treat legacy labels such as `attack_type`, `attack_stage`, `trojan_callback`, or `c2` as final output classes.
- Retrieval should support session cards and official CSV output: `stage1_submission.csv` and `stage2_submission.csv`.

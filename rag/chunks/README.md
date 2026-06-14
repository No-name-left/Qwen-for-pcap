# RAG Chunks

This directory stores chunked RAG knowledge for the session-level competition workflow.

Current expected output:

- `rag_chunks.jsonl`: chunks derived from `rag/knowledge/**/*.md`.
- Chunk metadata copied from source front matter when available.
- Stable chunk ids based on `doc_id` and local chunk index.

The chunks are used by keyword + metadata retrieval as the current baseline. They should support official stage / technique code judgment, not legacy event-level JSON output.

Safety constraints:

- Do not include test answers, expected labels, MTA answers PDF concrete answers, raw private PCAP paths, or secrets.
- If a source document is legacy event-card or PCAP-level material, keep that context in metadata or reports so it is not mistaken for final session-level policy.
- Vector or hybrid indexes are optional future enhancements and are not required to use this chunk set.

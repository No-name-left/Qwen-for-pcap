# Official-code RAG rebuild report

- Gate: `PASS`
- Source documents: 94
- Chunks generated: 98
- Index chunks: 98
- Unique index tokens: 1513
- Chunks output: `rag/chunks/rag_chunks.jsonl`
- Index output: `rag/index/keyword_index.json`

## Build logs

```text
# RAG chunks report

- Source documents: 94
- Chunks generated: 98
- Output: `rag/chunks/rag_chunks.jsonl`

## Chunks by category

- aggregation_policy: 5
- attack_stages: 6
- attack_types: 12
- competition_labels: 24
- false_positive_rules: 9
- protocols: 9
- signatures: 23
- tool_fields: 10

# Keyword index report

- Input chunks: `rag/chunks/rag_chunks.jsonl`
- Indexed chunks: 98
- Unique tokens: 1513
- Output: `rag/index/keyword_index.json`

## Retrieval mode

- Current mode: keyword.
- Future modes reserved: vector, hybrid.
```

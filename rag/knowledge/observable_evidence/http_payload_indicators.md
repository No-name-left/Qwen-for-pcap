---
doc_id: observable_http_payload_indicators
title: Bounded plaintext HTTP evidence
category: observable_evidence
attack_types: [normal, exploit, backdoor, other_attack]
attack_stages: [none, initial_access, persistence, command_and_control]
keywords: [plaintext_http, suspicious_payload_snippets, suspicious_http_parameters, HTTP body, redacted]
source_type: project_distilled
safe_for_llm: true
---

# Meaning

`plaintext_http` means request metadata or bounded body context was visible in the capture. Snippet fields contain only redacted, truncated context around classification-relevant strings; header-presence booleans never contain their values.

# Closed-set use and limits

Injection or traversal text supports `TA01_02`; commands sent to a recognizable existing webshell support `TA11_01`; multipart script upload supports `TA03_01`. Ordinary methods, forms, cookies, uploads, status codes, or a keyword without behavioral context do not prove attack, execution, authentication success, or persistence. Prefer the current session context over RAG.

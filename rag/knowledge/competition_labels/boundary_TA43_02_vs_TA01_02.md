---
doc_id: competition_boundary_TA43_02_vs_TA01_02
title: Boundary TA43_02 vulnerability scan versus TA01_02 exploitation
category: competition_labels
attack_types: [other_attack, exploit]
attack_stages: [reconnaissance, initial_access]
keywords: [TA43_02, TA01_02, vulnerability scan, exploit, payload, CVE probe, command injection, scanner boundary]
source_type: official_or_distilled
safe_for_llm: true
---

# Boundary: TA43_02 vs TA01_02

`TA43_02` is probing for weaknesses. Evidence is enumeration, version checks, scanner paths, CVE probes, and vulnerability discovery without a payload that attempts compromise.

`TA01_02` is exploitation. Evidence is payload-bearing traffic, exploit signatures, command injection, SQL injection, XSS payloads, SMB exploit behavior, or protocol actions consistent with attempted compromise.

When both are present in the same record, prefer `TA01_02` only if the exploit payload or attempted compromise evidence is explicit.

If the record shows only scanner-like discovery, keep it as `TA43_02`.

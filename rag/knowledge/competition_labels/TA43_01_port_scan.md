---
doc_id: competition_TA43_01_port_scan
title: TA43_01 port scan
category: competition_labels
attack_types: [port_scan]
attack_stages: [reconnaissance]
keywords: [TA43_01, TA43, port scan, scan_group, many ports, SYN, failed connections, reconnaissance]
source_type: official_or_distilled
safe_for_llm: true
---

# TA43_01 port scan

Use `TA43_01` when the record evidence shows port discovery against one or more hosts. Strong evidence includes many destination ports from the same source, short low-byte connections, many failed connection states, SYN-style probing, sequential or broad destination-port coverage, or an explicit scan-group record.

`TA43_01` is reconnaissance. It should map to stage `TA43`.

Do not require payload content for `TA43_01`. The key evidence is connection fanout and probing shape, not successful compromise.

# Normal and background avoidance

Do not classify ordinary browsing, a few failed connections, DNS/NBNS noise, or normal service retries as `TA43_01`. A single connection to an unusual port is not enough.

When a multi-port scan is already represented as one `scan_group`, classify the group once and avoid duplicate per-session scan outputs.

# Boundary cues

Prefer `TA43_02` instead when the record shows vulnerability enumeration such as web scanner paths, version checks, CVE probes, scanner signatures, or service-specific probe strings.

Prefer `TA01_02` when exploit payload evidence or attempted compromise is present.

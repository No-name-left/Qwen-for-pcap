---
doc_id: observable_scan_probe_timing
title: Scan burst and vulnerability-probe timing
category: observable_evidence
attack_types: [port_scan, other_attack, exploit]
attack_stages: [reconnaissance, initial_access]
keywords: [scan_group, scan_duration, probe_rate, burstiness_score, URI fanout, TA43_01, TA43_02]
source_type: project_distilled
safe_for_llm: true
---

# Closed-set use

High port or host fanout, short failures, and a concentrated probe rate support `TA43_01`. Repeated service-specific paths, scanner user agents, CVE probes, URI-path fanout, and 404 patterns support `TA43_02` even when ports are few.

# Limits

Rate or burstiness alone does not distinguish port discovery from vulnerability scanning. Query-value changes on one login path are not URI-path fanout, and exploit-shaped scanner probes do not prove exploitation.

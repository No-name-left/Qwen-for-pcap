---
doc_id: competition_boundary_TA43_01_vs_TA43_02
title: Boundary TA43_01 port scan versus TA43_02 vulnerability scan
category: competition_labels
attack_types: [port_scan, other_attack]
attack_stages: [reconnaissance]
keywords: [TA43_01, TA43_02, port scan, vulnerability scan, service enumeration, CVE probe, scanner boundary]
source_type: official_or_distilled
safe_for_llm: true
---

# Boundary: TA43_01 vs TA43_02

`TA43_01` is port discovery. Choose it for many destination ports, short failed connections, scan-group records, and broad connection fanout when the record does not show service-specific vulnerability probing.

`TA43_02` is vulnerability discovery. Choose it when the scanner probes versions, web paths, CVE indicators, service banners, or vulnerability-specific checks.

Do not upgrade port fanout to `TA43_02` just because scanning is suspicious. Require vulnerability-enumeration evidence.

Do not downgrade vulnerability scanner evidence to `TA43_01` when the record clearly contains probe strings or scanner alerts.

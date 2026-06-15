---
doc_id: competition_boundary_TA01_01_vs_TN01_01
title: Boundary TA01_01 brute force versus TN01_01 ordinary failed access
category: competition_labels
attack_types: [other_attack, normal]
attack_stages: [initial_access, none]
keywords: [TA01_01, TN01_01, brute force, failed login, authentication, normal retry, false positive]
source_type: official_or_distilled
safe_for_llm: true
---

# Boundary: TA01_01 vs TN01_01

`TA01_01` requires repeated authentication attempts or brute-force evidence. Useful signals include many failed logins, many short login sessions, repeated attempts against SSH/FTP/RDP/SMB/HTTP login, and brute-force signatures.

`TN01_01` is appropriate for isolated failed logins, normal retries, ordinary failed business access, or flow-only records without enough authentication detail.

Do not use reset-heavy traffic alone as brute force. Require authentication context or brute-force signature evidence.

Do not hide obvious repeated login attacks inside `TN01_01` when the record contains strong repeated-authentication evidence.

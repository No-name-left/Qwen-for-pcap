---
doc_id: competition_bruteforce_boundary
title: Password brute force boundary
category: competition_labels
attack_types: [other_attack, normal]
attack_stages: [initial_access]
keywords: [TA01_01, brute force, bruteforce, login failures, SSH, FTP, RDP, authentication]
source_type: official_or_distilled
safe_for_llm: true
---

# Password brute force boundary

Use `TA01_01` when a record shows repeated authentication attempts, many failures, repeated login sessions, Suricata brute-force signatures, or protocol evidence for SSH, FTP, RDP, SMB, HTTP login, or similar authentication endpoints.

Single failed logins, isolated resets, or normal connection retries are weak evidence and should generally map to `TN01_01`.

Do not rely on source IP reputation or domain reputation. Use only local behavior in the current PCAP.

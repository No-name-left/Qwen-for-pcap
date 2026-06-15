---
doc_id: competition_TA01_01_bruteforce
title: TA01_01 password brute force
category: competition_labels
attack_types: [other_attack]
attack_stages: [initial_access]
keywords: [TA01_01, TA01, brute force, bruteforce, password attack, login failures, SSH, FTP, RDP, authentication]
source_type: official_or_distilled
safe_for_llm: true
---

# TA01_01 password brute force

Use `TA01_01` when the record shows repeated attempts to authenticate to a service. Strong evidence includes many failed logins, repeated SSH/FTP/RDP/SMB/HTTP-login sessions, authentication brute-force signatures, many short login attempts, or a high failed-attempt ratio against the same service.

`TA01_01` is initial access. It should map to stage `TA01`.

# Normal and background avoidance

Do not classify one or two failed logins, ordinary retries, reset-heavy but non-authentication traffic, or missing-payload flow rows as brute force by default.

If the record has only weak generic connection failures and no authentication context, prefer `TN01_01`.

# Boundary cues

Prefer `TA01_02` when the evidence is exploit payload or vulnerability exploitation rather than repeated credential attempts.

Prefer `TN01_01` for isolated failed business access or low-signal flow-only records.

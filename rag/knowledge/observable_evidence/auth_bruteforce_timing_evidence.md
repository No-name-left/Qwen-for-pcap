---
doc_id: observable_auth_bruteforce_timing
title: Authentication attempt timing evidence
category: observable_evidence
attack_types: [other_attack, normal]
attack_stages: [initial_access, none]
keywords: [auth_attempt_group, failed_login_count, attempt_rate, inter_attempt_intervals, failure_burst, success_after_failures_hint, FTP, SSH, HTTP login, TA01_01, TN01_01]
source_type: project_distilled
safe_for_llm: true
---

# Closed-set use

A short same-source, same-target authentication burst with repeated explicit failures supports `TA01_01`. Use attempt count, time span, attempt rate, inter-attempt summary, failure count, failure burst, credential-field evidence, protocol context, and success-after-failures evidence together.

# Limits

Connection resets, one failed login, or repeated encrypted SSH/HTTPS sessions without authentication-failure evidence are weak. Fast SSO redirects, health checks, and normal retries may be `TN01_01`. Timing never reveals hidden passwords or proves account compromise.

---
doc_id: observable_auth_bruteforce_indicators
title: Authentication brute-force indicators
category: observable_evidence
attack_types: [other_attack, normal]
attack_stages: [initial_access, none]
keywords: [auth_indicators, SSH, FTP, HTTP login, repeated failures, TA01_01, TN01_01]
source_type: project_distilled
safe_for_llm: true
---

# Meaning and support

Repeated same-endpoint SSH/FTP/HTTP authentication attempts with failure evidence, credential-field presence, or success after failures support `TA01_01`. Password values are never retained.

# Limits and boundaries

An authentication port, one login, or repeated connections without authentication/failure evidence is weak and may be `TN01_01`. Connection failures are not equivalent to password failures. A few normal retries, SSO redirects, and health checks are common false positives.

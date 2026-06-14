---
doc_id: "signature_bruteforce"
title: "Bruteforce signatures"
category: "signatures"
attack_types: ["other_attack"]
attack_stages: ["initial_access"]
keywords: ["bruteforce", "SSH", "FTP", "RDP", "login"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Bruteforce signatures

## Evidence

Bruteforce signatures identify repeated authentication attempts against services such as SSH, FTP, RDP, web login, or mail protocols.

## Judgment

Map to other_attack with subtype brute_force because the output vocabulary lacks a dedicated brute-force type.

## Stage mapping

Bruteforce maps to initial_access.

## Boundaries

Connection failures without authentication context are not enough.

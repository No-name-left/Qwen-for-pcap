---
doc_id: "initial_access_stage"
title: "Initial access stage"
category: "attack_stages"
attack_types: ["exploit", "other_attack"]
attack_stages: ["initial_access"]
keywords: ["initial_access", "exploit", "bruteforce", "web attack", "SMB exploit"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Initial access stage

## Evidence

Initial access evidence includes exploit attempts, vulnerability signatures, brute-force login behavior, or malicious web requests aimed at gaining entry.

## Judgment

Use initial_access when the event is an attempt to compromise the target or authenticate without authorization.

## Stage mapping

SMB exploit, web exploit, and brute-force events commonly map here.

## Boundaries

Do not use initial_access just because a service was contacted; require attack intent or exploit/login evidence.

## Source grounding

Grounded by MITRE ATT&CK Initial Access tactic pages, Microsoft MS17-010, Suricata exploit categories, and protocol evidence. Exploit signatures, SMB exploit indicators, web exploit strings, and brute-force login attempts are the main event-card evidence for `initial_access`.

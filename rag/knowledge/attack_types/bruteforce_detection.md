---
doc_id: "bruteforce_detection"
title: "Bruteforce detection"
category: "attack_types"
attack_types: ["other_attack"]
attack_stages: ["initial_access"]
keywords: ["bruteforce", "SSH", "FTP", "RDP", "login failures", "authentication"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Bruteforce detection

## Evidence

Bruteforce evidence includes many authentication attempts, repeated failures, many usernames, or IDS signatures naming SSH, FTP, web, or RDP brute force.

## Judgment

The supported attack_type vocabulary has no dedicated brute_force label, so classify strong brute-force evidence as other_attack with subtype brute_force.

## Stage mapping

Bruteforce normally maps to initial_access because it attempts to gain entry through credentials.

## Boundaries

Repeated failed connections are not always authentication failures. Confirm that the protocol and evidence actually involve login attempts.

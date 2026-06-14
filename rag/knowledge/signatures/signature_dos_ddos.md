---
doc_id: "signature_dos_ddos"
title: "DoS and DDoS signatures"
category: "signatures"
attack_types: ["other_attack"]
attack_stages: ["initial_access"]
keywords: ["DoS", "DDoS", "flood", "SYN flood", "amplification"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# DoS and DDoS signatures

## Evidence

DoS/DDoS signatures indicate traffic intended to exhaust service capacity or network resources. Evidence may include flood signatures, many sources, high rate, or protocol amplification.

## Judgment

Map to other_attack with subtype dos_ddos.

## Stage mapping

Use initial_access as the closest supported active-attack stage and explain the availability focus.

## Boundaries

High traffic is not automatically DoS. Require flood pattern or signature.

---
doc_id: "signature_protocol_anomaly"
title: "Protocol anomaly signatures"
category: "signatures"
attack_types: ["normal", "other_attack"]
attack_stages: ["none", "initial_access"]
keywords: ["protocol anomaly", "invalid checksum", "unknown code", "malformed"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Protocol anomaly signatures

## Evidence

Protocol anomaly signatures describe malformed packets, invalid checksums, unknown codes, parser errors, or unusual protocol states. These are often low-specificity signals.

## Judgment

Classify as attack only when anomalies align with exploit, malware, flood, or repeated suspicious behavior. Otherwise normal/none with low confidence is safer.

## Stage mapping

Most isolated anomalies map to none. Exploit-linked anomalies may map to initial_access.

## Boundaries

Do not high-confidence classify attacks from invalid checksum or unknown code alone.

## Relevant event card fields

Check Zeek weird/notice evidence and tshark protocol fields for invalid checksum, unknown code, ICMPv6, UDPv6, malformed, or protocol anomaly indicators. If these low-specificity anomalies are the only evidence, prefer `TN01_01` with low confidence.

## Source grounding

Protocol decoder anomalies are weak by themselves. Without exploit, callback, malware, flood, or scan evidence in the same session, they should remain low confidence and usually map to `TN01_01`.

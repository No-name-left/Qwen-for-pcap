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

Check `suricata_alerts.signature` and `suricata_alerts.category` for phrases such as invalid checksum, unknown code, ICMPv6, UDPv6, malformed, or protocol anomaly. If `suricata_features.top_alert_signatures` only contains these low-specificity alerts and there is no exploit, C2, malware, flood, or scan evidence, prefer `normal/none` with low confidence.

## Source grounding

Grounded by Suricata decoder/app-layer alert semantics and local rules for invalid checksum, unknown code, ICMPv6, UDPv6, malformed, and protocol anomaly messages. These alerts are IDS evidence but weak by themselves. Without exploit, C2, malware, flood, or scan evidence in the same event card, they should remain low confidence and often map to `normal / none`.

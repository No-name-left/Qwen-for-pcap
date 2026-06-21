---
doc_id: "protocol_anomaly_low_confidence"
title: "Protocol anomaly low confidence policy"
category: "false_positive_rules"
attack_types: ["normal", "other_attack"]
attack_stages: ["none", "initial_access"]
keywords: ["invalid checksum", "unknown code", "protocol anomaly", "malformed", "low confidence"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Protocol anomaly low confidence policy

## Evidence

Invalid checksums, unknown ICMP codes, parser weirds, and generic malformed-packet alerts are often caused by capture offload, network devices, benign implementation differences, or parser limits.

## Judgment

Treat isolated protocol anomalies as low-confidence evidence. Classify as normal/none unless accompanied by exploit signatures, malware alerts, flood behavior, or repeated suspicious context.

## Stage mapping

Most isolated anomalies have stage none. If tied to a concrete exploit attempt, initial_access may be justified.

## Boundaries

Do not high-confidence label attacks from checksum or unknown-code alerts alone.

## Relevant event card fields

Low-confidence anomaly handling should inspect Zeek `weird.log`, connection history/state, tshark protocol fields, flags, and packet counts. Invalid checksum, unknown code, ICMPv6, and UDPv6 anomalies should not by themselves override otherwise empty application summaries or low connection counts. Stronger judgment requires accompanying exploit, callback, malware, or flood evidence.

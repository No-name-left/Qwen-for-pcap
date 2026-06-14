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

Low-confidence anomaly handling should inspect `suricata_alerts.signature`, `suricata_alerts.category`, `suricata_alerts.severity`, and `suricata_features.top_alert_signatures`. Invalid checksum, unknown code, ICMPv6, and UDPv6 alerts should not by themselves override otherwise empty `tshark_features` or low `zeek_features.conn_count`. Stronger judgment requires accompanying exploit, C2, malware, or flood evidence.

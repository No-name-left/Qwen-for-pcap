---
doc_id: "protocol_icmp_icmpv6"
title: "ICMP and ICMPv6 interpretation"
category: "protocols"
attack_types: ["normal", "other_attack"]
attack_stages: ["none", "reconnaissance"]
keywords: ["ICMP", "ICMPv6", "checksum", "unknown code", "ping"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# ICMP and ICMPv6 interpretation

## Evidence

ICMP is used for reachability, errors, and diagnostics. ICMPv6 is essential for IPv6 neighbor discovery and control messages.

## Judgment

ICMP sweeps can support reconnaissance when many hosts are probed. Generic invalid checksum or unknown code alerts are usually low-signal protocol anomalies.

## Stage mapping

Reconnaissance mapping requires sweep-like behavior or explicit scan alerts.

## Boundaries

Do not high-confidence classify attacks from checksum or unknown-code alerts alone unless exploit, malware, or flood evidence is also present.

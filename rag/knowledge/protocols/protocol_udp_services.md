---
doc_id: "protocol_udp_services"
title: "UDP service interpretation"
category: "protocols"
attack_types: ["normal", "port_scan", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "command_and_control"]
keywords: ["UDP", "DNS", "NTP", "QUIC", "SNMP", "UDP scan"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# UDP service interpretation

## Evidence

UDP carries many normal services such as DNS, NTP, QUIC, SNMP, and VoIP. UDP scanning may show probes to many ports with few responses.

## Judgment

Suspicious UDP evidence includes broad port probing, reflection-amplification patterns, DNS tunneling, or malware C2 signatures.

## Stage mapping

UDP scans map to reconnaissance; DNS tunnel or malware contact can map to command_and_control.

## Boundaries

UDP lacks connection setup, so failed_conn_rate may be less direct. Use service context and alerts.

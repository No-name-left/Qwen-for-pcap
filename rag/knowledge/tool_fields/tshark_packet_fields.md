---
doc_id: "tshark_packet_fields"
title: "Tshark packet fields"
category: "tool_fields"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["tshark", "packet_count", "tcp_syn_count", "tcp_ack_count", "frame.len"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Tshark packet fields

## Evidence

Tshark-derived fields are packet-level extractions. packet_count, frame length, source and destination IPs, ports, TCP flags, HTTP host, URI, DNS query, and TLS SNI can describe traffic shape and visible protocol values.

## Judgment

Tshark does not produce a security verdict. Use its fields as supporting evidence for volume, port spread, protocol presence, and sample strings.

## Stage mapping

High unique_dst_ports and SYN-heavy traffic can support reconnaissance; suspicious URI or SNI values can support exploit or callback only with context.

## Boundaries

Missing fields are normal when a protocol is absent or encrypted. Empty HTTP fields in TLS traffic do not mean the event is benign by itself.

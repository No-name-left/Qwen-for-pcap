---
doc_id: "protocol_tls_sni"
title: "TLS SNI interpretation"
category: "protocols"
attack_types: ["normal", "c2", "trojan_callback"]
attack_stages: ["none", "command_and_control"]
keywords: ["TLS", "SNI", "tls_sni", "certificate", "HTTPS"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# TLS SNI interpretation

## Evidence

TLS SNI reveals the requested server name during handshake when present. It is a useful external-name clue for encrypted traffic.

## Judgment

SNI can support callback analysis when paired with suspicious domains, rare destinations, repeated timing, or IDS alerts.

## Stage mapping

TLS-based malware contact maps to command_and_control when remote coordination is supported.

## Boundaries

SNI is not payload. It cannot prove C2 by itself and may be absent due to encrypted client hello, IP-only access, or older clients.

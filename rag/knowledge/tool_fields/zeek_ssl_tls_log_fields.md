---
doc_id: "zeek_ssl_tls_log_fields"
title: "Zeek SSL and TLS log fields"
category: "tool_fields"
attack_types: ["normal", "c2", "trojan_callback"]
attack_stages: ["none", "command_and_control"]
keywords: ["Zeek", "ssl.log", "tls.log", "tls_sni", "SNI", "certificate"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Zeek SSL and TLS log fields

## Evidence

Zeek TLS logs can expose SNI, certificate metadata, TLS versions, and handshake features. SNI is useful as a visible destination name even when HTTP payload is encrypted.

## Judgment

Suspicious TLS evidence includes malware-related domains, unusual certificate patterns, rare SNI values, or matching IDS alerts.

## Stage mapping

TLS callback or beaconing can support command_and_control when combined with repetition or signatures.

## Boundaries

SNI alone cannot prove C2. Many benign services use TLS and content is encrypted.

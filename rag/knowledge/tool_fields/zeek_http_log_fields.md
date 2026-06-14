---
doc_id: "zeek_http_log_fields"
title: "Zeek HTTP log fields"
category: "tool_fields"
attack_types: ["normal", "exploit", "trojan_callback", "c2"]
attack_stages: ["none", "initial_access", "command_and_control"]
keywords: ["Zeek", "http.log", "http_uris", "Host", "URI", "status_code"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Zeek HTTP log fields

## Evidence

Zeek HTTP logs provide host, URI, method, status code, user agent, and content metadata when available. Event-card samples such as http_uri_samples can reveal web exploit attempts or malware callback paths.

## Judgment

Suspicious web evidence includes exploit-like parameters, traversal strings, encoded commands, unusual downloads, or IDS signatures tied to HTTP.

## Stage mapping

Web exploit maps to initial_access; malware HTTP checkin or callback maps to command_and_control.

## Boundaries

Benign web browsing is diverse. A strange URI is not conclusive without repetition, dangerous syntax, alert support, or suspicious destination context.

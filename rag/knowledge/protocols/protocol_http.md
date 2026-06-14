---
doc_id: "protocol_http"
title: "HTTP protocol interpretation"
category: "protocols"
attack_types: ["normal", "exploit", "trojan_callback", "c2"]
attack_stages: ["none", "initial_access", "command_and_control"]
keywords: ["HTTP", "Host", "URI", "GET", "POST", "status_code"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# HTTP protocol interpretation

## Evidence

HTTP fields reveal hostnames, paths, parameters, methods, status codes, and sometimes user agents. URI samples can expose exploit strings or malware callback paths.

## Judgment

Web exploit evidence includes SQL injection, XSS, traversal, command injection, upload abuse, or alert-backed malicious downloads.

## Stage mapping

Exploit-like requests map to initial_access; malware checkins over HTTP map to command_and_control.

## Boundaries

Normal web traffic is noisy. Require dangerous syntax, repeated attempts, abnormal host, alert category, or payload context.

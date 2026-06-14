---
doc_id: "protocol_tcp_flags"
title: "TCP flags and connection behavior"
category: "protocols"
attack_types: ["normal", "port_scan", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access"]
keywords: ["TCP", "SYN", "ACK", "RST", "FIN", "tcp.flags"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# TCP flags and connection behavior

## Evidence

TCP flags help distinguish connection attempts from established sessions. Many SYN packets without ACKs, resets, or short failed attempts can indicate scanning or denied access.

## Judgment

SYN-heavy traffic across many ports supports port_scan. Established ACK traffic with normal byte exchange is less suspicious without other evidence.

## Stage mapping

Scanning maps to reconnaissance; repeated failed access attempts may support initial_access only with authentication or exploit context.

## Boundaries

TCP flags are low-level signals. Middleboxes and resets can create unusual patterns, so combine with port diversity and connection summaries.

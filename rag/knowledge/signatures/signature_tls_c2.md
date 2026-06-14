---
doc_id: "signature_tls_c2"
title: "TLS C2 signature"
category: "signatures"
attack_types: ["c2", "trojan_callback"]
attack_stages: ["command_and_control"]
keywords: ["TLS C2", "SNI", "certificate", "JA3", "HTTPS callback"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# TLS C2 signature

## Evidence

TLS C2 signatures indicate encrypted command traffic. Evidence can include SNI, certificate anomalies, JA3-like fingerprints when present, or IDS categories naming encrypted C2.

## Judgment

Classify as c2 or trojan_callback based on signature wording and traffic pattern.

## Stage mapping

The stage is command_and_control.

## Boundaries

TLS encryption hides content. SNI or certificate clues should be paired with alert or repetition.

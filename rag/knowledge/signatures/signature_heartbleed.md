---
doc_id: "signature_heartbleed"
title: "Heartbleed signature"
category: "signatures"
attack_types: ["exploit"]
attack_stages: ["initial_access"]
keywords: ["Heartbleed", "OpenSSL", "TLS", "CVE-2014-0160", "exploit"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Heartbleed signature

## Evidence

Heartbleed signatures refer to attempts to abuse the OpenSSL heartbeat vulnerability. Evidence typically appears in TLS-related traffic with signature text naming Heartbleed or malformed heartbeat behavior.

## Judgment

Classify as exploit when the signature clearly indicates Heartbleed attempt or response.

## Stage mapping

The stage maps to initial_access because the attacker attempts to disclose memory or gain sensitive material.

## Boundaries

TLS traffic alone is normal. Require Heartbleed-specific signature or malformed heartbeat evidence.

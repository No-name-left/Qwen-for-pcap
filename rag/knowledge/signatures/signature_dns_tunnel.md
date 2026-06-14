---
doc_id: "signature_dns_tunnel"
title: "DNS tunnel signature"
category: "signatures"
attack_types: ["other_attack", "c2"]
attack_stages: ["command_and_control"]
keywords: ["DNS tunnel", "long domain", "TXT", "base64", "covert channel"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# DNS tunnel signature

## Evidence

DNS tunnel signatures indicate DNS being used as a covert transport. Evidence may include long encoded labels, many subdomains, TXT queries, high query rate, or explicit tunnel alerts.

## Judgment

Classify as c2 when the tunnel supports command/control; otherwise use other_attack with subtype dns_tunnel.

## Stage mapping

DNS tunnels usually map to command_and_control because they carry covert communication.

## Boundaries

Long domains are not always malicious. CDN and tracking domains can be long; require repetition, encoding pattern, or alert.

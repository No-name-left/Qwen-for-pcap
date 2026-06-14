---
doc_id: "normal_dns_vs_dns_tunnel"
title: "Normal DNS versus DNS tunnel"
category: "false_positive_rules"
attack_types: ["normal", "c2", "other_attack"]
attack_stages: ["none", "command_and_control"]
keywords: ["DNS", "DNS tunnel", "long domain", "NXDOMAIN", "TXT"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Normal DNS versus DNS tunnel

## Evidence

Normal DNS includes diverse domains, CDN names, service discovery, and repeated lookups from caches or applications.

## Judgment

DNS tunnel suspicion needs encoded long labels, many generated subdomains, unusual TXT use, high rate, or explicit tunnel alerts.

## Stage mapping

Tunneling or C2 lookup behavior maps to command_and_control.

## Boundaries

A long or unfamiliar domain alone is weak.

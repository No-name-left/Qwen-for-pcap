---
doc_id: competition_anonymized_ip_domain_policy
title: Anonymized IP and domain policy
category: competition_labels
attack_types: [normal, port_scan, exploit, backdoor, trojan_callback, c2, other_attack]
attack_stages: [none, reconnaissance, initial_access, persistence, command_and_control]
keywords: [anonymous IP, anonymized domain, no reputation, same PCAP relationship, TA43, TA01, TA11, TN01]
source_type: official_or_distilled
safe_for_llm: true
---

# Anonymized IP and domain policy

IP addresses and domains may be anonymized. The classifier must not depend on reputation, geolocation, WHOIS, passive DNS, or external threat intelligence.

Within the same PCAP, relationship features may still be useful:

- one source contacting many ports on one destination;
- one source contacting many destinations;
- many sources contacting one destination;
- repeated periodic sessions between the same endpoints;
- service, protocol, alert, byte, packet, duration, and connection-state patterns.

Do not carry entity behavior from one PCAP into another PCAP.

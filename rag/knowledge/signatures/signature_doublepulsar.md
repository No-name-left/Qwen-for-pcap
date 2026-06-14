---
doc_id: "signature_doublepulsar"
title: "DOUBLEPULSAR beacon response"
category: "signatures"
attack_types: ["backdoor", "trojan_callback", "c2"]
attack_stages: ["persistence", "command_and_control"]
keywords: ["DOUBLEPULSAR", "beacon", "implant", "backdoor", "SMB"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# DOUBLEPULSAR beacon response

## Evidence

DOUBLEPULSAR is commonly described as a post-exploitation implant or backdoor associated with SMB intrusion activity. A beacon response signature suggests communication with an implant rather than a generic vulnerability probe.

## Judgment

Do not simply map DOUBLEPULSAR to exploit. If the event shows beacon or implant response behavior, backdoor, trojan_callback, or c2 may better describe the traffic depending on whether it indicates installed access or active control.

## Stage mapping

The stage is often persistence for implanted access or command_and_control for active beacon/control exchange.

## Boundaries

Use surrounding evidence carefully. If only a weak or generic SMB anomaly exists, do not infer DOUBLEPULSAR.

## Relevant event card fields

Look for `suricata_alerts.signature` containing DOUBLEPULSAR Beacon Response, `suricata_alerts.category` that indicates malware, implant, or backdoor behavior, and SMB context such as port 445. A post-exploitation implant signal should be considered for `backdoor`, `trojan_callback`, or `c2`, with `command_and_control` when the event shows beacon/control exchange.

## Source grounding

Grounded by NHS Digital DoublePulsar references, Help Net Security, ExtraHop, Avast/SecPod backup references, Microsoft MS17-010 context, and local ET Open rule metadata. DoublePulsar is closer to backdoor / implant / post-exploitation / beacon behavior than ordinary exploit. A DOUBLEPULSAR Beacon Response should be interpreted with event evidence and may map to `backdoor`, `trojan_callback`, or `c2`, often with `command_and_control` when beacon/control exchange is visible.

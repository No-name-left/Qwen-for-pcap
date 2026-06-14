---
doc_id: "signature_strrat"
title: "STRRAT CnC Checkin signature"
category: "signatures"
attack_types: ["c2", "trojan_callback"]
attack_stages: ["command_and_control"]
keywords: ["STRRAT", "CnC Checkin", "C2", "malware", "RAT"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# STRRAT CnC Checkin signature

## Evidence

A STRRAT CnC Checkin signature indicates traffic associated with the STRRAT remote access Trojan contacting command infrastructure. The signature text is malware-family specific and stronger than a generic anomaly.

## Judgment

When this signature appears with outbound flow evidence, classify as c2 or trojan_callback. c2 is preferred when the signature explicitly says CnC or command activity.

## Stage mapping

The stage is command_and_control because checkin behavior exchanges status or instructions after infection.

## Boundaries

Confirm the event actually contains the alert. Do not place STRRAT knowledge into an event with no related signature.

## Relevant event card fields

Look for `suricata_alerts.signature` containing STRRAT or CnC Checkin, `suricata_alerts.category` such as Malware Command and Control, and `suricata_features.top_alert_signatures` showing repeated STRRAT hits. These fields support `attack_type=c2` and `attack_stage=command_and_control` when the event is outbound or otherwise consistent with Remote Access Trojan checkin behavior.

## Source grounding

Grounded by stable public STRRAT sources: Malpedia `jar.strrat`, NHS Digital CC-3867, Microsoft threat naming, ThreatFox, and local ET Open Suricata rule metadata. STRRAT is treated as a Java-based RAT / Remote Access Trojan with credential stealing, keylogging, and C2/checkin behavior. In event cards, STRRAT CnC Checkin or Malware Command and Control wording in `suricata_alerts.signature` or `suricata_alerts.category` can support `c2 / command_and_control`. No current test answer is encoded here.

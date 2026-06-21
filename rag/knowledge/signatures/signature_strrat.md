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

Look for STRRAT/CnC wording in available protocol content, repeated outbound check-ins, callback URI or service patterns, and timing/byte asymmetry consistent with Remote Access Trojan behavior. These indicators support `TA11_02` when corroborated.

## Source grounding

Grounded by stable public STRRAT sources: Malpedia `jar.strrat`, NHS Digital CC-3867, Microsoft threat naming, and ThreatFox. STRRAT is treated as a Java-based RAT with credential stealing, keylogging, and C2/check-in behavior. No current test answer is encoded here.

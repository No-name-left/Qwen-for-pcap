---
doc_id: competition_backdoor_implant_access_callback_boundary
title: Backdoor implant, access, and callback boundary
category: competition_labels
attack_types: [backdoor, c2, trojan_callback]
attack_stages: [persistence, command_and_control]
keywords: [TA01_02, TA03_01, TA11_01, TA11_02, exploit request, multipart/form-data, webshell filename, payload delivery, backdoor endpoint, cmd parameter, implant, backdoor access, callback, C2, beacon]
source_type: official_or_distilled
safe_for_llm: true
---

# Backdoor implant, access, and callback boundary

Use `TA01_02` for the exploit request itself: command injection, SQLi, path traversal, malicious parameters, or vulnerability-trigger traffic. Do not treat the exploit request alone as proof that persistence succeeded.

Use `TA03_01` when the record indicates network-visible implantation or payload delivery, such as multipart/form-data, upload paths, transferred webshell-like filenames, script/executable delivery, implant placement, durable backdoor creation, or persistence-specific alerts.

Use `TA11_01` when the record indicates interactive access to an already present backdoor, such as reverse shell use, repeated access to a webshell/backdoor endpoint, `cmd`/`command`/`exec` parameters, or backdoor protocol interaction.

Use `TA11_02` when the record indicates malware callback or command-and-control check-in, including periodic beaconing, RAT check-in signatures, suspicious callback URIs, or recurring outbound C2-like sessions.

Normal software update checks, telemetry, and periodic business traffic are not enough for `TA11_02` without stronger malware or C2 evidence.

Do not classify from IP/domain reputation.

PCAP evidence is network-side. It may show an upload, exploit string, or command parameter, but it cannot directly prove host-side execution or durable persistence success.

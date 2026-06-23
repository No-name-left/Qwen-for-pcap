---
doc_id: observable_backdoor_access_vs_callback
title: Backdoor access versus callback evidence
category: observable_evidence
attack_types: [backdoor, trojan_callback, c2, normal]
attack_stages: [command_and_control, none]
keywords: [backdoor_access_indicators, c2_indicators, webshell, command parameter, periodic, beacon, TA11_01, TA11_02]
source_type: project_distilled
safe_for_llm: true
---

# Meaning and support

Attacker-initiated requests to a recognizable webshell/control path with command parameters or interactive output favor `TA11_01`. Repeated victim-initiated connections to one remote endpoint, regular intervals, small similar transfers, or repeated DNS/SNI favor `TA11_02`.

# Limits and boundaries

A shell keyword in an initial injection may be `TA01_02`, and an upload is `TA03_01`. Regular HTTPS health checks, updates, DNS retries, and telemetry can look periodic; ordinary encrypted traffic is not enough for `TA11_02`. Network direction is a hint, not proof of endpoint ownership.

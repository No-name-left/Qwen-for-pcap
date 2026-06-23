---
doc_id: observable_file_upload_and_implant_hints
title: File upload and implant hints
category: observable_evidence
attack_types: [backdoor, exploit, normal]
attack_stages: [persistence, initial_access, none]
keywords: [implant_indicators, multipart, upload, webshell, php, jsp, executable transfer, TA03_01]
source_type: project_distilled
safe_for_llm: true
---

# Meaning and support

Multipart upload plus a script/webshell extension, server-directed executable/archive transfer, or a file-write-like request supports `TA03_01` as a network-observed deployment attempt. `transferred_files_summary` is metadata only; no file content is extracted.

# Limits and boundaries

Upload does not prove persistence or successful installation. A request exploiting an upload vulnerability without deployment evidence can be `TA01_02`; later command use of an existing uploaded shell can be `TA11_01`. Normal business uploads and static files are not implants.

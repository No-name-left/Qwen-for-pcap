# Runtime profiles and prompt budgets

`configs/runtime_profiles.yaml` is the single cross-Linux runtime contract. Business code talks only to an OpenAI-compatible API; it does not import `torch_npu`, load model weights, or branch on Linux distribution.

## Profiles

- `ascend_openeuler_qwen35_27b`: local `qwen3.5` at `127.0.0.1:8000`, 4096-token model context, 3400-token/10200-character conservative prompt ceiling, thinking disabled.
- `nvidia_ubuntu_online_api`: endpoint, model and secret come from `LLM_*` variables. Context and prompt budgets can also be overridden by environment variables.
- `dry_run_mock`: deterministic CI/smoke profile. It makes no network call and says nothing about model accuracy.

Select a profile with `--runtime-profile` or `RUNTIME_PROFILE`. Never put an API key in YAML. `.env.local` is ignored by Git.

## Context policy

One prompt covers one `session` or `scan_group`, not a dataset and not an entire large PCAP. The useful context is the current structured record, same-PCAP aggregate fields already attached to it, feature-triggered decision-boundary cards, then top-ranked ordinary RAG.

When the budget is tight, prompt construction keeps official closed-set instructions and the current record first. It removes low-ranked ordinary RAG before targeted boundary cards, truncates long HTTP/DNS/TLS lists, and finally removes RAG if that is necessary to preserve core evidence. Prompt manifests record characters, conservative token estimates, profile, version and truncation status.

The Ascend profile leaves room inside `--max-model-len 4096` for the chat template and a short JSON completion. `max_prompt_tokens` is an estimate; final vLLM tokenizer counts remain authoritative during deployment.

# Bastion and VPN notes

The formal environment may require VPN plus bastion access. It may also block VS Code Remote, Codex, GitHub CLI, or direct internet access.

## Practical constraints

- Prepare a release package that can be uploaded through web file transfer.
- Keep the package self-contained for offline session-card, RAG retrieval, prompt generation, and CSV dry-run export.
- Do not depend on interactive cloud IDE features.
- Do not assume direct GitHub access from the competition host.

## Credential handling

- Keep SSH keys, tokens, and API keys outside the release package.
- Configure `LLM_BASE_URL`, `LLM_MODEL_NAME`, and `LLM_API_KEY` on the target host only when model execution is explicitly approved.
- `scripts/check_env.sh` only reports whether `LLM_API_KEY` exists and never prints its value.

# Remote OpenAI-compatible API readiness plan

Run configuration-only inspection first:

```bash
python3 scripts/check_remote_api_readiness.py --dry-run
```

It prints only whether credentials exist and their length—never their value. If `BASE_URL`, `MODEL`, and an API credential are complete, run one real readiness check. That makes at most one `GET /v1/models` and one minimal `POST /v1/chat/completions` with thinking disabled.

```bash
python3 scripts/check_remote_api_readiness.py
```

Configure an untracked `.env.local`:

```bash
LLM_BASE_URL=https://provider.example/v1
LLM_MODEL_NAME=exact-provider-model-id
LLM_API_KEY=replace-locally
```

HTTP 401 means credential/authentication failure; 402 usually means credits or billing; 403 means access is forbidden; 404 may mean the path or model name is wrong; timeouts/DNS errors may require network or proxy configuration. Provider support for OpenAI chat completions, Qwen thinking control, usage accounting, exact model ID, current price and credits must all be confirmed before a paired run.

The actual tiny paired run additionally requires `RUN_REAL_API_TEST=1`, a passing readiness report, and at most two selected records (two no-RAG plus two RAG calls). A rejected thinking-control extension is not retried during readiness because the call budget permits only one chat request; the next approved tiny test can use `--disable-extra-body`.

## Current development-environment result (2026-06-22)

- Configuration is complete and endpoint scope is remote; credential presence/length were checked without printing its value.
- One `/models` request returned HTTP 200 with 126 model entries. The configured model alias was not listed, but the provider accepted it in chat.
- One minimal chat returned HTTP 200, usage tokens, and accepted thinking-off chat-template parameters.
- Readiness status is `ready` with no detected proxy, credits, authentication, endpoint, or billing blocker.
- `RUN_REAL_API_TEST=1` is not set, so no paired real evaluation was executed this round.

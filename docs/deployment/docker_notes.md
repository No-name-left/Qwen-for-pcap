# Docker deployment notes

The competition environment may provide an organizer-maintained Docker image. Prefer the official image when available because it can include approved versions of Python, tshark, Zeek, Suricata, CUDA libraries, or local model serving tools.

## Expected usage

- Mount the project release package into the container.
- Mount input PCAPs and output directories as separate volumes.
- Keep tokens and endpoint settings outside the image.
- Do not bake `LLM_API_KEY`, Hugging Face tokens, cookies, or SSH keys into the image.

## Optional Docker check

`scripts/check_env.sh` reports whether Docker exists, but Docker is optional for the offline skeleton.

## Local model endpoint

If the organizer provides a model-serving container, expose an OpenAI-compatible endpoint such as:

```text
http://127.0.0.1:8000/v1
```

The default one-click scripts do not call this endpoint unless the user explicitly passes `--run-api`.

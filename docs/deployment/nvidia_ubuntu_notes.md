# NVIDIA Ubuntu deployment notes

Use the same Python/Zeek/TShark and CSV business pipeline as openEuler. Start a local OpenAI-compatible service or configure an online endpoint, then select `nvidia_ubuntu_online_api`. GPU/model loading belongs to that service and is not imported by repository business code.

Copy `configs/env.nvidia_ubuntu.example` to an untracked `.env.local` and replace endpoint/model/key locally. The profile allows environment overrides for model context and prompt budgets. Use `--disable-extra-body` when a provider rejects Qwen-specific chat-template arguments.

Ubuntu package names may differ from openEuler; installation commands belong in deployment notes, not classification branches.

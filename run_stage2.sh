#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "stage2 uses the same technique-first pipeline and exports technique_code"
exec bash "$ROOT/run_stage1.sh" --task-mode stage2 "$@"

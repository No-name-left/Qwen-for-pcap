#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "stage2 uses the same technique-first offline pipeline; stage_code is derived from technique_code"
exec bash "$ROOT/run_stage1.sh" "$@"

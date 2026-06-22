#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

DRY_RUN=false
TASK_MODE=stage1
ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --stage-results|--technique-results|--records)
      ARGS+=("$1" "$2")
      shift 2
      ;;
    --task-mode)
      TASK_MODE="$2"
      shift 2
      ;;
    --output|--report)
      ARGS+=("$1" "$2")
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ "$DRY_RUN" = true ]; then
  python3 scripts/export_competition_csv.py --task-mode "$TASK_MODE" --dry-run "${ARGS[@]}"
else
  python3 scripts/export_competition_csv.py --task-mode "$TASK_MODE" "${ARGS[@]}"
fi

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

DRY_RUN=true
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
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ "$DRY_RUN" = true ]; then
  python3 scripts/export_competition_csv.py --dry-run "${ARGS[@]}"
else
  python3 scripts/export_competition_csv.py "${ARGS[@]}"
fi

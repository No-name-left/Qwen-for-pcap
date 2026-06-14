#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

INCLUDE_OUTPUTS=false
for arg in "$@"; do
  case "$arg" in
    --include-outputs) INCLUDE_OUTPUTS=true ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

mkdir -p outputs/release docs
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="outputs/release/qwen_for_pcap_mainline_${STAMP}.tar.gz"

INCLUDES=(
  configs
  docs
  rag/knowledge
  rag/chunks
  rag/index
  rag/metadata
  rag/reports
  rag/sources
  scripts
  README.md
  README_DEPLOY.md
  SECURITY.md
  requirements.txt
  run_stage1.sh
  run_stage2.sh
  export_submission.sh
)

if [ "$INCLUDE_OUTPUTS" = true ]; then
  INCLUDES+=(outputs/session_cards outputs/rag_queries outputs/rag_retrieval outputs/submissions)
fi

tar \
  --exclude='_non_mainline_archive' \
  --exclude='.git' \
  --exclude='.venv' \
  --exclude='venv' \
  --exclude='__pycache__' \
  --exclude='*.pcap' \
  --exclude='*.pcapng' \
  --exclude='*.env' \
  --exclude='.env' \
  --exclude='*TOKEN*' \
  --exclude='*token*' \
  --exclude='*API_KEY*' \
  -czf "$ARCHIVE" \
  "${INCLUDES[@]}"

cat > docs/release_package_report.md <<EOF
# Release package report

- Archive: \`$ARCHIVE\`
- Include generated outputs: $INCLUDE_OUTPUTS
- Excludes by default: \`_non_mainline_archive/\`, raw PCAP/PCAPNG files, virtual environments, Git metadata, token-like files, local env files, and large old outputs.
- Intended transfer: upload the archive through the approved web file-transfer path if VPN/bastion constraints prevent direct Git access.
- Model API called: no
EOF

echo "wrote $ARCHIVE"

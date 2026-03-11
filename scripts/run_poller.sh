#!/usr/bin/env bash
# run_poller.sh — TCM Approval Poller
# Schedule via cron: */15 * * * * /opt/netscaler-ssl-auto/scripts/run_poller.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate 2>/dev/null || true
python -m src.tcm.tcm_poller --config config/settings.yaml

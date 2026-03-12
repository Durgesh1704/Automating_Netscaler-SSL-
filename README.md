# NetScaler SSL Certificate Automation

**Enterprise-grade, state-aware orchestration for automated SSL certificate updates across 250 Citrix ADCs.**

---

## Architecture Overview

```
SCV (Secure Credential Vault)
        │
        ▼
   [ DETECTED ]  ──► Intelligent Inspector
        │
   [ INSPECTED ]  ──► Chain Walker (recursive, N-depth)
        │
   [ DELTA ANALYZED ]  ──► Scenario A (leaf swap) / Scenario B (full chain)
        │
   [ UAT DEPLOYED ]  ──► ADM config_job  (per-node result parsing)
        │
   [ UAT VALIDATED ]  ──► TLS Handshake + chain_depth check
        │
   [ TCM PENDING ]  ──► ITSM ticket  (stateless poller, 48h TTL)
        │
   [ TCM APPROVED ]  ──► Rollback pre-generated
        │
   ┌────┴────────────────────┐
   │                         │
[ WAVE 1 ]  5%          [ TCM_REJECTED ] ──► ABORTED
[ WAVE 2 ]  25%
[ WAVE 3 ]  100%
   │
[ COMPLETED ]  ──► Audit log + Notify + TCM close
```

---

## State Machine

| State | Description |
|---|---|
| `DETECTED` | New cert bundle found in SCV |
| `INSPECTED` | Chain walked, SANs validated, notBefore checked |
| `DELTA_ANALYZED` | Live ADC chain compared, Scenario A/B decided |
| `UAT_DEPLOYED` | Dynamic Nitro payload executed on UAT ADCs |
| `UAT_VALIDATED` | TLS handshake verified, chain_depth ≥ 2 confirmed |
| `TCM_PENDING` | ITSM ticket created, stateless poller waiting |
| `TCM_APPROVED` | Rollback pre-generated, wave queue built |
| `PROD_WAVE_1` | Canary 5% (~12 ADCs), gate threshold: >1 fail = halt |
| `PROD_WAVE_2` | Regional 25% (~62 ADCs), gate threshold: >3 fail = halt |
| `PROD_WAVE_3` | Full fleet 100% (~250 ADCs) |
| `COMPLETED` | Audit logged, TCM closed, stakeholders notified |
| `VALIDATION_FAILED` | Pre-generated rollback executed immediately |
| `ROLLBACK` | Rollback in progress |
| `ROLLED_BACK` | Original chain restored |
| `TCM_REJECTED` | Change rejected → ABORTED |
| `ABORTED` | TTL expired or manual cancel |

---

## Project Structure

```
netscaler-ssl-automation/
├── src/
│   ├── inspector/          # Intelligent cert bundle inspector
│   ├── delta/              # Delta analysis engine (Scenario A/B)
│   ├── executor/           # ADM Nitro API job builder + executor
│   ├── validator/          # TLS handshake + chain validator
│   ├── tcm/                # ITSM/TCM integration (ServiceNow/Jira)
│   ├── notifier/           # SMTP + Teams notifications
│   ├── state/              # State machine + persistent state store
│   └── orchestrator.py     # Main orchestration entry point
├── config/
│   ├── settings.yaml       # All configuration (ADM, ITSM, waves)
│   └── wave_strategy.yaml  # Wave batching strategy
├── tests/                  # Unit + integration tests
├── scripts/
│   └── run_poller.sh       # TCM approval poller (cron-scheduled)
├── docs/
│   ├── runbook.md          # Operational runbook
│   └── enterprise_technical_handover.md  # Enterprise teammate handover
├── requirements.txt
└── docker-compose.yml
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure
cp config/settings.yaml.example config/settings.yaml
# Edit config/settings.yaml with your ADM, ITSM, SCV endpoints

# 3. Run the orchestrator (triggered by SCV webhook or manual)
python src/orchestrator.py --cert-bundle /path/to/bundle.pem --target-certkey cert_vpn_prod

# 4. Run the TCM approval poller (schedule via cron every 15 min)
bash scripts/run_poller.sh
```

---

## Key Design Decisions

- **Stateless processes** — TCM poll loop is a separate cron job, not a sleeping script
- **Pre-generated rollbacks** — computed and stored *before* Wave 1 executes
- **Per-node ADM parsing** — parent job status is never trusted; every node result parsed individually
- **Wave gating** — automated go/no-go with configurable failure thresholds per wave
- **Idempotency** — cert SHA256 fingerprint used as dedup key; safe to retry at any state
- **48h TCM TTL** — auto-expires orphaned tickets and alerts on-call

---

## Requirements

- Python 3.10+
- Citrix ADM 13.1+
- ServiceNow / Jira (configurable)
- Redis or PostgreSQL (state store)
- SMTP or MS Graph API (notifications)

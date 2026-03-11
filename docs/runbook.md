# Operational Runbook — NetScaler SSL Certificate Automation

## 1. Normal Operation

### Trigger a cert update
```bash
python src/orchestrator.py \
  --cert-bundle /secure/vault/new_cert_bundle.pem \
  --target-certkey cert_vpn_prod \
  --vserver-type VPN
```

The orchestrator will:
1. Inspect the bundle and persist job state
2. Run delta analysis against all 250 ADCs via ADM
3. Deploy to UAT and validate
4. Create a TCM change ticket and exit
5. The cron poller picks up approval after TCM is approved

### Check job status
```bash
# List all jobs
sqlite3 state/jobs.db "SELECT job_id, status, ts_updated FROM cert_jobs ORDER BY ts_updated DESC LIMIT 20;"

# Full detail on a specific job
sqlite3 state/jobs.db "SELECT payload FROM cert_jobs WHERE job_id='<JOB_ID>';" | python -m json.tool
```

---

## 2. TCM Poller

The poller runs every 15 minutes via cron:
```
*/15 * * * * /opt/netscaler-ssl-auto/scripts/run_poller.sh >> /var/log/tcm_poller.log 2>&1
```

Manual run:
```bash
python -m src.tcm.tcm_poller
```

---

## 3. Rollback

Rollbacks are automated — if any wave gate fails, the pre-generated rollback payload executes immediately.

To manually trigger rollback on a ROLLED_BACK job (e.g., verify state):
```bash
python src/orchestrator.py --resume-job <JOB_ID>
```

---

## 4. Common Issues

### "chain_depth < 2" in validation
**Cause:** `link ssl certkey` step silently failed on one or more ADCs.
**Fix:** Check ADM job per-node results. Re-run with `--resume-job` after manual verification.

### "FutureDatedCertError"
**Cause:** The new cert's `notBefore` is more than 24h in the future.
**Fix:** Wait until the cert's validity window opens, then re-trigger.

### TCM TTL expired
**Cause:** The change ticket was not approved within 48 hours.
**Fix:** Re-submit: create a new cert update trigger with the same bundle.

### UAT validation fails
**Cause:** TLS handshake to UAT VIP failed.
**Fix:** Check UAT ADC connectivity, then check the ADM UAT job per-node results.

---

## 5. Audit Query

All jobs are retained for 90 days. To pull an audit report:
```bash
sqlite3 state/jobs.db "
  SELECT job_id, target_certkey, status, ts_created, ts_updated, total_deployed
  FROM cert_jobs
  WHERE ts_created >= date('now', '-90 days')
  ORDER BY ts_created DESC;
"
```

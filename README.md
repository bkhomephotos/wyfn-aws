# wyfn-aws

The dedicated AWS account for WY Filing Notices' filing worker and card release. Nothing here is deployed.

- `infra/template.yaml`: CloudFormation for the whole account (network, egress proxy, VPC endpoints, worker group, card KMS key and secrets, release function, ledger, CloudTrail and alarms, and the site's backup bucket). Create the stack only after BK approves the cost (about $45 a month with the worker on 7:45am to 8:15pm New York; about $60 if it runs around the clock; the backup bucket adds cents). Check it with `cfn-lint infra/template.yaml` (`pip install cfn-lint`) before every change: it must report nothing.
- Worker releases: `WorkerCommit` (empty by default: no worker image, no worker) is BK's approval of one release. Setting it in Update stack makes EC2 Image Builder build the worker image from exactly that commit of `wyfn-filing-worker` (it must carry a `worker-v*` tag), using a read-only GitHub token in Secrets Manager (`wyfn/github-read`, value set by BK). A push, a new tag or a moved tag changes nothing in AWS. The launch template writes the worker's settings (`/etc/wyfn/worker.env`, nothing secret) at boot. A failed build rolls the update back; the old image keeps running.
- Backups: `BackupBucket` holds the site's hourly encrypted copies (wyfilingnotices `netlify/lib/backup.ts`). Versioned, every version locked 35 days (Object Lock, governance), TLS only. The site's user `SiteBackupUser` may only PutObject under `v1/`: no read, list or delete. Files are encrypted on the site to BK's backup public key; only his private key, kept offline, opens them (`npm run backup-restore` in the site repo).
- `release/`: the release function. `decide.ts` is the decision (kill switch, grant signature and life, single use, slot switches, $65.00 automatic ceiling, attended mode, BK's passkey approvals, hours, hourly and daily caps); `handler.ts` is the Lambda wrapper. `grantSpec.ts` is byte for byte the site's.
- `alerts/parse.ts`: card alert emails matched against this account's own release log; unmatched turns the kill switch on.
- `scripts/card-provision.sh`, `scripts/card-session.sh`: BK stores a card, or a session security code, from AWS CloudShell. Values never touch Claude, GitHub, logs or chat.

    npm ci && npm test

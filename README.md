# wyfn-aws

The dedicated AWS account for WY Filing Notices' filing worker and card release. Nothing here is deployed.

- `infra/template.yaml`: CloudFormation for the whole account (network, egress proxy, VPC endpoints, worker group, card KMS key and secrets, release function, ledger, CloudTrail and alarms). Create the stack only after BK approves the cost (about $59 to $62 a month).
- `release/`: the release function. `decide.ts` is the decision (kill switch, grant signature and life, single use, slot switches, $65.00 automatic ceiling, attended mode, BK's passkey approvals, hours, hourly and daily caps); `handler.ts` is the Lambda wrapper. `grantSpec.ts` is byte for byte the site's.
- `alerts/parse.ts`: card alert emails matched against this account's own release log; unmatched turns the kill switch on.
- `scripts/card-provision.sh`, `scripts/card-session.sh`: BK stores a card, or a session security code, from AWS CloudShell. Values never touch Claude, GitHub, logs or chat.

    npm ci && npm test

#!/usr/bin/env bash
# The attended pilot's security code for a session (when the card was stored with --no-cvv). Encrypted here with the
# card key (BK may encrypt, only the release function may decrypt) and kept with an expiry; after it, payments on
# that card stop until BK runs this again. Run in AWS CloudShell in the dedicated account.
#
#   bash scripts/card-session.sh debit 8        (hours, at most 12)
set -euo pipefail
slot="${1:?usage: card-session.sh debit|chase HOURS}"; hours="${2:-8}"
[[ "$slot" == debit || "$slot" == chase ]] || exit 2
(( hours >= 1 && hours <= 12 )) || { echo "1 to 12 hours"; exit 2; }
key=$(aws kms list-aliases --query "Aliases[?AliasName=='alias/wyfn-card'].TargetKeyId" --output text)
read -rsp "Security code: " cvv; echo
[[ "$cvv" =~ ^[0-9]{3,4}$ ]] || { echo "3 or 4 digits"; exit 2; }
blob=$(printf '%s' "$cvv" | aws kms encrypt --key-id "$key" --plaintext fileb:///dev/stdin --encryption-context purpose=wyfn-cvv-session,slot="$slot" --query CiphertextBlob --output text)
unset cvv
exp=$(( $(date +%s) + hours * 3600 ))
aws dynamodb put-item --table-name wyfn-release --item "{\"pk\":{\"S\":\"cvv#$slot\"},\"blob\":{\"B\":\"$blob\"},\"expiresAt\":{\"N\":\"$exp\"}}"
echo "Security code set for $hours hours."

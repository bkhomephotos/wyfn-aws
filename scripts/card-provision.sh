#!/usr/bin/env bash
# Stores one card in the dedicated AWS account's vault. Run by BK in AWS CloudShell (signed in to the NEW account
# with his passkey), never on a shared machine. Nothing typed is echoed, put on a command line, written to disk or
# sent anywhere but Secrets Manager. Claude, GitHub and chat never see a card value.
#
#   bash scripts/card-provision.sh debit        (or: chase)
#
# Add --no-cvv to store the number and expiry only; the security code is then given per session with card-session.sh.
set -euo pipefail
slot="${1:?usage: card-provision.sh debit|chase [--no-cvv]}"
[[ "$slot" == debit || "$slot" == chase ]] || { echo "slot must be debit or chase"; exit 2; }
set +o history 2>/dev/null || true
read -rsp "Card number (digits only): " number; echo
read -rsp "Expiry month (MM): " mm; echo
read -rsp "Expiry year (YY): " yy; echo
cvv=""
if [[ "${2:-}" != "--no-cvv" ]]; then read -rsp "Security code: " cvv; echo; fi
read -rp "Name on card: " name
read -rp "Billing street: " street
read -rp "Billing ZIP: " zip
[[ "$number" =~ ^[0-9]{13,19}$ && "$mm" =~ ^[0-9]{2}$ && "$yy" =~ ^[0-9]{2}$ ]] || { echo "number or expiry not in the expected shape; nothing stored"; exit 2; }
[[ -z "$cvv" || "$cvv" =~ ^[0-9]{3,4}$ ]] || { echo "security code not 3 or 4 digits; nothing stored"; exit 2; }
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
json=$(printf '{"number":"%s","expMonth":"%s","expYear":"%s","cvv":%s,"name":"%s","street":"%s","zip":"%s"}' "$number" "$mm" "$yy" "$( [[ -n "$cvv" ]] && printf '"%s"' "$cvv" || printf null )" "$(esc "$name")" "$(esc "$street")" "$(esc "$zip")")
# printf is a shell builtin: the value goes to the CLI on stdin, never in a process's arguments.
printf '%s' "$json" | aws secretsmanager put-secret-value --secret-id "wyfn/card/$slot" --secret-string file:///dev/stdin --query VersionId --output text
unset number mm yy cvv json
echo "Stored."
echo "Now put this card's last four digits in the Automation settings on the dashboard (slot $slot)."

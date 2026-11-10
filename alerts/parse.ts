// Card alerts by email (SES inbound on a dedicated address), turned into facts and matched against THIS account's
// own release log, not the site's: an alert that matches no card release here turns the kill switch on by itself,
// whatever the site says. Then the facts (never a card number: issuer, last four, amount, time, merchant) are posted
// to the site, signed with ALERT_INGEST_KEY, so the site pauses too and emails BK.
//
// The issuers' wording is NOT YET RECORDED. The patterns below are placeholders shaped like Chase's usual "A charge
// of ($USD) 61.44 at WY SOS ... card ending in 1234" text; Phase 0 replaces them with a real sample from each card.
// Anything that comes from an issuer's address and can't be read counts as unmatched (fails closed).

export interface ParsedAlert {
  issuer: 'chase' | 'debit_bank';
  kind: 'charge' | 'decline' | 'refund' | 'unknown';
  last4: string | null;
  amountCents: number | null;
  merchant: string | null;
}

export interface IssuerPattern {
  issuer: 'chase' | 'debit_bank';
  fromDomain: RegExp;
  charge: RegExp;
  decline: RegExp;
  refund: RegExp;
  last4: RegExp;
  merchant: RegExp;
}

export const PLACEHOLDER_PATTERNS: IssuerPattern[] = [
  {
    issuer: 'chase',
    fromDomain: /@(?:[a-z0-9-]+\.)*chase\.com$/i,
    charge: /(?:charge|transaction|purchase) of \(?\$?(?:USD\)?\s*)?([\d,]+\.\d{2})/i,
    decline: /declin/i,
    refund: /\b(refund|credit) of\b/i,
    last4: /ending (?:in )?(\d{4})\b/i,
    merchant: /\bat ([A-Z0-9 *&.'#/-]{3,40}?)(?: has| was| on|\.|$)/,
  },
];

const cents = (s: string) => Math.round(Number(s.replace(/,/g, '')) * 100);

export function parseAlert(from: string, subject: string, text: string, patterns: IssuerPattern[] = PLACEHOLDER_PATTERNS): ParsedAlert | null {
  const addr = (/<([^>]+)>/.exec(from)?.[1] ?? from).trim();
  const p = patterns.find((x) => x.fromDomain.test(addr));
  if (!p) return null; // not an issuer: ignored (spam to the alert address)
  const body = `${subject}\n${text}`.slice(0, 20_000);
  const amount = p.charge.exec(body)?.[1];
  const last4 = p.last4.exec(body)?.[1] ?? null;
  const kind: ParsedAlert['kind'] = p.decline.test(body) ? 'decline' : p.refund.test(body) ? 'refund' : amount ? 'charge' : 'unknown';
  return { issuer: p.issuer, kind: amount && last4 ? kind : 'unknown', last4, amountCents: amount ? cents(amount) : null, merchant: p.merchant.exec(body)?.[1]?.trim() ?? null };
}

export interface ReleaseRecord {
  slot: 'debit' | 'chase';
  amountCents: number;
  at: string;
  ref: string;
}

/** Does this charge alert match one release here (same card's last four, same cents, within 6 hours after it)? */
export function matchRelease(a: ParsedAlert, alertAt: string, releases: ReleaseRecord[], last4BySlot: Record<string, string | null>, taken: Set<string>): { matched: true; key: string } | { matched: false; why: string } {
  if (a.kind === 'refund') return { matched: true, key: 'refund' };
  if (a.kind === 'unknown' || a.last4 === null || a.amountCents === null) return { matched: false, why: 'unreadable alert from the issuer' };
  const t = Date.parse(alertAt);
  const hits = releases.filter((r) => last4BySlot[r.slot] === a.last4 && r.amountCents === a.amountCents && t >= Date.parse(r.at) - 300_000 && t <= Date.parse(r.at) + 6 * 3_600_000 && !taken.has(`${r.at}|${r.ref}`));
  if (!hits.length) return { matched: false, why: `no release of $${(a.amountCents / 100).toFixed(2)} on ••${a.last4} before this alert` };
  const first = hits.sort((x, y) => x.at.localeCompare(y.at))[0];
  return { matched: true, key: `${first.at}|${first.ref}` };
}

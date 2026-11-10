import type { KeyObject } from 'node:crypto';
import { approvalMatchesGrant, verifyGrant, verifyPasskeyApproval, type GrantClaims, type PasskeyKey, type Slot } from './grantSpec';

// The release function's decision, pure. It is the only code in either account that can decrypt a card, and it
// trusts nothing it is told: the site's grant is checked here against the site's PUBLIC key (the site cannot decrypt;
// this function cannot sign), and every limit below is this account's own, kept in DynamoDB, changeable only by BK
// through the AWS console. A compromised site or worker can't raise any of them.
//
// Refuses, in this order: kill switch; bad, altered, expired or over-long grant; a test-mode grant on live cards; a
// disabled card slot; a total over Wyoming's online maximum; an automatic grant over the automatic limit or in the
// attended pilot; an approval that is not BK's passkey over exactly this payment, or that is reused; outside payment
// hours; a reused grant id; the hourly count or daily total reached. Only then: the card for that one slot.

/** Wyoming e-files a license tax of at most $500; at 2.4% that is $512.00 at checkout. Nothing above is ever released. */
export const ONLINE_MAX_TOTAL_CENTS = 51_200;
export const ONLINE_MAX_STATE_FEE_CENTS = 50_000;
/** BK's automatic limit, fee included. The stored setting may be lower, never higher. */
export const AUTOMATIC_CEILING_CENTS = 6_500;

export interface ReleaseConfig {
  killSwitch: boolean;
  /** Every grant needs BK's passkey approval (the attended pilot). */
  attended: boolean;
  normalMaxCents: number;
  perHour: number;
  perDayCents: number;
  /** New York time, "HH:MM". null: any time. */
  hours: { start: string; end: string } | null;
  slots: Record<Slot, { enabled: boolean }>;
  /** Test-mode grants (Stripe test orders) are refused unless this is on, and it is never on with real cards stored. */
  acceptTestGrants: boolean;
  /** The site's grant-signing PUBLIC key. */
  sitePublicKey: KeyObject;
  /** BK's passkeys, registered here by BK (never taken from the site at run time). */
  passkeys: PasskeyKey[];
  rp: { origin: string; rpId: string };
}

export interface Ledger {
  /**
   * Records the release atomically, or refuses: the grant id unused, the approval id (if any) unused, this hour's count
   * under `perHour`, today's total plus `amountCents` within `perDayCents`. All or nothing.
   */
  record(r: { jti: string; approvalId: string | null; hourKey: string; dayKey: string; amountCents: number; perHour: number; perDayCents: number; slot: Slot; ref: string; at: string }): Promise<{ ok: true } | { ok: false; why: string }>;
}

export type Decision = { ok: true; claims: GrantClaims } | { ok: false; why: string };

const nyParts = (now: Date) => {
  const f = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(now);
  const g = (t: string) => f.find((p) => p.type === t)!.value;
  return { day: `${g('year')}-${g('month')}-${g('day')}`, hour: g('hour') === '24' ? '00' : g('hour'), minute: g('minute') };
};

export function configProblems(c: ReleaseConfig): string[] {
  const p: string[] = [];
  if (!Number.isInteger(c.normalMaxCents) || c.normalMaxCents < 0 || c.normalMaxCents > AUTOMATIC_CEILING_CENTS) p.push('normalMaxCents out of range');
  if (!Number.isInteger(c.perHour) || c.perHour < 0 || c.perHour > 30) p.push('perHour out of range');
  if (!Number.isInteger(c.perDayCents) || c.perDayCents < 0 || c.perDayCents > 500_000) p.push('perDayCents out of range');
  if (c.sitePublicKey.asymmetricKeyType !== 'ed25519') p.push('site key is not Ed25519');
  return p;
}

export async function decide(token: unknown, c: ReleaseConfig, ledger: Ledger, now: Date): Promise<Decision> {
  const problems = configProblems(c);
  if (problems.length) return { ok: false, why: `release config invalid: ${problems.join('; ')}` };
  if (c.killSwitch) return { ok: false, why: 'kill switch is on' };
  const nowS = Math.floor(now.getTime() / 1000);
  const v = verifyGrant(token, c.sitePublicKey, nowS);
  if (!v.ok) return { ok: false, why: v.why };
  const g = v.claims;
  if (g.mode === 'test' && !c.acceptTestGrants) return { ok: false, why: 'test-mode grant refused' };
  if (!c.slots[g.slot]?.enabled) return { ok: false, why: `card slot ${g.slot} is switched off` };
  if (g.amountCents > ONLINE_MAX_TOTAL_CENTS || g.stateFeeCents > ONLINE_MAX_STATE_FEE_CENTS) return { ok: false, why: 'over Wyoming’s online maximum' };

  let approvalId: string | null = null;
  if (g.authority === 'automatic') {
    if (c.attended) return { ok: false, why: 'attended mode: every payment needs BK’s approval' };
    if (g.amountCents > c.normalMaxCents) return { ok: false, why: 'over the automatic limit without an approval' };
  } else {
    const a = g.approval!;
    const mismatch = approvalMatchesGrant(g, nowS);
    if (mismatch) return { ok: false, why: mismatch };
    if (g.amountCents > c.normalMaxCents && a.payload.scope !== 'exception') return { ok: false, why: 'an over-limit payment needs an over-limit approval' };
    const bad = verifyPasskeyApproval(a, c.passkeys, c.rp);
    if (bad) return { ok: false, why: `approval: ${bad}` };
    approvalId = a.payload.id;
  }

  const ny = nyParts(now);
  if (c.hours) {
    const t = `${ny.hour}:${ny.minute}`;
    if (t < c.hours.start || t >= c.hours.end) return { ok: false, why: 'outside payment hours' };
  }
  const recorded = await ledger.record({ jti: g.jti, approvalId, hourKey: `${ny.day}T${ny.hour}`, dayKey: ny.day, amountCents: g.amountCents, perHour: c.perHour, perDayCents: c.perDayCents, slot: g.slot, ref: g.ref, at: now.toISOString() });
  if (!recorded.ok) return { ok: false, why: recorded.why };
  return { ok: true, claims: g };
}

/** In-memory ledger with the same all-or-nothing rules, for tests. */
export class MemoryLedger implements Ledger {
  jtis = new Set<string>();
  approvals = new Set<string>();
  hours = new Map<string, number>();
  days = new Map<string, number>();
  releases: { jti: string; slot: Slot; amountCents: number; at: string; ref: string }[] = [];
  async record(r: Parameters<Ledger['record']>[0]): Promise<{ ok: true } | { ok: false; why: string }> {
    if (this.jtis.has(r.jti)) return { ok: false, why: 'grant already used' };
    if (r.approvalId && this.approvals.has(r.approvalId)) return { ok: false, why: 'approval already used' };
    if ((this.hours.get(r.hourKey) ?? 0) + 1 > r.perHour) return { ok: false, why: 'hourly limit reached' };
    if ((this.days.get(r.dayKey) ?? 0) + r.amountCents > r.perDayCents) return { ok: false, why: 'daily limit reached' };
    this.jtis.add(r.jti);
    if (r.approvalId) this.approvals.add(r.approvalId);
    this.hours.set(r.hourKey, (this.hours.get(r.hourKey) ?? 0) + 1);
    this.days.set(r.dayKey, (this.days.get(r.dayKey) ?? 0) + r.amountCents);
    this.releases.push({ jti: r.jti, slot: r.slot, amountCents: r.amountCents, at: r.at, ref: r.ref });
    return { ok: true };
  }
}

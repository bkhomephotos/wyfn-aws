// The release function's decision (release/decide.ts) and the alert parser's matching (alerts/parse.ts). Every
// refusal the review's acceptance criteria name, plus the $65 automatic limit and the attended pilot, enforced in
// this account whatever the site signs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { decide, MemoryLedger, type ReleaseConfig } from '../release/decide';
import { approvalChallenge, signGrant, type ApprovalPayload, type GrantClaims, type SignedApproval } from '../release/grantSpec';
import { matchRelease, parseAlert } from '../alerts/parse';

const site = generateKeyPairSync('ed25519');
const attacker = generateKeyPairSync('ed25519');
const bk = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const NOW = new Date('2026-11-10T16:00:00Z'); // 11:00am New York
const nowS = Math.floor(NOW.getTime() / 1000);
let seq = 0;
const jti = () => `J${String(++seq).padStart(21, '0')}`;

function cfg(over: Partial<ReleaseConfig> = {}): ReleaseConfig {
  return {
    killSwitch: false,
    attended: false,
    normalMaxCents: 6_500,
    perHour: 10,
    perDayCents: 150_000,
    hours: { start: '08:00', end: '20:00' },
    slots: { debit: { enabled: true }, chase: { enabled: true } },
    acceptTestGrants: false,
    sitePublicKey: site.publicKey,
    passkeys: [{ credentialId: 'bk1', spki: bk.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') }],
    rp: { origin: 'https://wyfilingnotices.com', rpId: 'wyfilingnotices.com' },
    ...over,
  };
}

function claims(over: Partial<GrantClaims> = {}): GrantClaims {
  return { v: 1, typ: 'wyfn-pay-grant', jti: jti(), ref: 'WY-ABCDEFGH', filingId: '2020-000123456', reportYear: 2026, invoice: '1'.repeat(24), amountCents: 6_144, stateFeeCents: 6_000, processingFeeCents: 144, slot: 'chase', attempt: 1, workerId: 'aws-worker-1', generation: 2, authority: 'automatic', approval: null, mode: 'live', iat: nowS - 5, exp: nowS + 295, ...over };
}

function approved(p: Partial<ApprovalPayload>, key = bk): SignedApproval {
  const payload: ApprovalPayload = { v: 1, typ: 'wyfn-pay-approval', id: `ap_${'a'.repeat(22)}`, ref: 'WY-ABCDEFGH', filingId: '2020-000123456', reportYear: 2026, stateFeeCents: 20_000, processingFeeCents: 480, totalCents: 20_480, attempt: 1, scope: 'exception', iat: nowS - 60, exp: nowS + 86_400, ...p };
  const authData = Buffer.concat([createHash('sha256').update('wyfilingnotices.com').digest(), Buffer.from([0x05, 0, 0, 0, 9])]);
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: approvalChallenge(payload), origin: 'https://wyfilingnotices.com' }));
  const sig = sign('sha256', Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), { key: key.privateKey, dsaEncoding: 'der' });
  return { payload, assertion: { credentialId: 'bk1', authenticatorData: authData.toString('base64url'), clientDataJSON: clientData.toString('base64url'), signature: sig.toString('base64url') } };
}

const tok = (c: GrantClaims, key = site.privateKey) => signGrant(c, key);
const run = (t: string, c = cfg(), l = new MemoryLedger(), at = NOW) => decide(t, c, l, at);

test('grantSpec here is byte for byte the site’s (shared format)', () => {
  const here = readFileSync(new URL('../release/grantSpec.ts', import.meta.url));
  let site = Buffer.alloc(0);
  try {
    site = readFileSync('/home/claude/wyfilingnotices/netlify/lib/automation/grantSpec.ts');
  } catch {
    return; // the site repo isn't beside this one: CI compares the pinned hash instead
  }
  assert.equal(createHash('sha256').update(here).digest('hex'), createHash('sha256').update(site).digest('hex'));
});

test('a standard $61.44 automatic grant is released once', async () => {
  const l = new MemoryLedger();
  const t = tok(claims());
  assert.equal((await run(t, cfg(), l)).ok, true);
  assert.deepEqual(await run(t, cfg(), l), { ok: false, why: 'grant already used' });
});

test('refused: expired, altered, signed by another key, kill switch, test grant, disabled slot, outside hours', async () => {
  assert.deepEqual(await run(tok(claims({ iat: nowS - 400, exp: nowS - 100 }))), { ok: false, why: 'grant expired' });
  const [p, payload, s] = tok(claims()).split('.');
  const tampered = Buffer.from(Buffer.from(payload, 'base64url').toString().replace('6144', '9144')).toString('base64url');
  assert.equal((await run(`${p}.${tampered}.${s}`)).ok, false);
  assert.deepEqual(await run(tok(claims(), attacker.privateKey)), { ok: false, why: 'bad signature' });
  assert.deepEqual(await run(tok(claims()), cfg({ killSwitch: true })), { ok: false, why: 'kill switch is on' });
  assert.deepEqual(await run(tok(claims({ mode: 'test' }))), { ok: false, why: 'test-mode grant refused' });
  assert.deepEqual(await run(tok(claims()), cfg({ slots: { debit: { enabled: true }, chase: { enabled: false } } })), { ok: false, why: 'card slot chase is switched off' });
  const nine = new Date('2026-11-11T02:00:00Z'); // 9:00pm New York
  const s9 = Math.floor(nine.getTime() / 1000);
  assert.deepEqual(await run(tok(claims({ iat: s9 - 5, exp: s9 + 295 })), cfg(), new MemoryLedger(), nine), { ok: false, why: 'outside payment hours' });
});

test('the $65 automatic limit and the attended pilot hold here even if the site signs something else', async () => {
  assert.deepEqual(await run(tok(claims({ amountCents: 6_501, stateFeeCents: 6_357, processingFeeCents: 144 }))), { ok: false, why: 'over the automatic limit without an approval' });
  assert.deepEqual(await run(tok(claims()), cfg({ attended: true })), { ok: false, why: 'attended mode: every payment needs BK’s approval' });
  assert.deepEqual(await run(tok(claims({ amountCents: 51_300, stateFeeCents: 50_100, processingFeeCents: 1_200 }))), { ok: false, why: 'over Wyoming’s online maximum' });
  // A config that tries to raise the automatic limit is refused outright.
  assert.equal((await run(tok(claims()), cfg({ normalMaxCents: 10_000 }))).ok, false);
});

test('over $65 with BK’s passkey approval for exactly this payment: released once; the same approval never again', async () => {
  const l = new MemoryLedger();
  const a = approved({});
  const over = { amountCents: 20_480, stateFeeCents: 20_000, processingFeeCents: 480, authority: 'approval' as const, approval: a };
  assert.equal((await run(tok(claims(over)), cfg(), l)).ok, true);
  assert.deepEqual(await run(tok(claims(over)), cfg(), l), { ok: false, why: 'approval already used' });
});

test('approvals that do not authorize the grant are refused here', async () => {
  const over = { amountCents: 20_480, stateFeeCents: 20_000, processingFeeCents: 480, authority: 'approval' as const };
  assert.deepEqual(await run(tok(claims({ ...over, approval: approved({}, generateKeyPairSync('ec', { namedCurve: 'P-256' })) }))), { ok: false, why: 'approval: bad passkey signature' });
  assert.deepEqual(await run(tok(claims({ ...over, approval: approved({ totalCents: 20_400, processingFeeCents: 400 }) }))), { ok: false, why: 'approval is for another amount' });
  assert.deepEqual(await run(tok(claims({ ...over, approval: approved({ scope: 'attended' }) }))), { ok: false, why: 'an over-limit payment needs an over-limit approval' });
  assert.deepEqual(await run(tok(claims({ ...over, approval: approved({ ref: 'WY-ZZZZZZZZ' }) }))), { ok: false, why: 'approval is for another filing' });
  // Attended pilot: a $61.44 payment with an attended approval goes.
  assert.equal((await run(tok(claims({ authority: 'approval', approval: approved({ stateFeeCents: 6_000, processingFeeCents: 144, totalCents: 6_144, scope: 'attended' }) })), cfg({ attended: true }))).ok, true);
});

test('hourly and daily caps are this account’s own', async () => {
  const l = new MemoryLedger();
  const c = cfg({ perHour: 2, perDayCents: 20_000 });
  assert.equal((await run(tok(claims()), c, l)).ok, true);
  assert.equal((await run(tok(claims()), c, l)).ok, true);
  assert.deepEqual(await run(tok(claims()), c, l), { ok: false, why: 'hourly limit reached' });
  const later = new Date(NOW.getTime() + 3_600_000);
  const l2 = new MemoryLedger();
  for (let i = 0; i < 3; i++) assert.equal((await decide(signGrant(claims({ iat: nowS + 3_600, exp: nowS + 3_890 }), site.privateKey), cfg({ perDayCents: 20_000 }), l2, later)).ok, true);
  assert.deepEqual(await decide(signGrant(claims({ iat: nowS + 3_600, exp: nowS + 3_890 }), site.privateKey), cfg({ perDayCents: 20_000 }), l2, later), { ok: false, why: 'daily limit reached' });
});

test('alert parser: a charge that matches a release here is matched; anything else is unmatched (kill switch)', () => {
  const a = parseAlert('Chase <no.reply.alerts@chase.com>', 'Your Ink Business card was charged', 'A charge of ($USD) 61.44 at WY SOS ANNUAL RPT has been authorized on 11/10/2026 on your card ending in 1111.')!;
  assert.equal(a.kind, 'charge');
  assert.equal(a.amountCents, 6_144);
  assert.equal(a.last4, '1111');
  const releases = [{ slot: 'chase' as const, amountCents: 6_144, at: '2026-11-10T16:00:00Z', ref: 'WY-ABCDEFGH' }];
  const last4 = { chase: '1111', debit: '2222' };
  assert.equal(matchRelease(a, '2026-11-10T16:01:00Z', releases, last4, new Set()).matched, true);
  assert.equal(matchRelease({ ...a, amountCents: 49_999 }, '2026-11-10T16:01:00Z', releases, last4, new Set()).matched, false);
  assert.equal(matchRelease(a, '2026-11-10T16:01:00Z', releases, last4, new Set(['2026-11-10T16:00:00Z|WY-ABCDEFGH'])).matched, false, 'one release, one alert');
  const unreadable = parseAlert('alerts@chase.com', 'Account notice', 'Something about your card.')!;
  assert.equal(matchRelease(unreadable, '2026-11-10T16:01:00Z', releases, last4, new Set()).matched, false);
  assert.equal(parseAlert('someone@example.com', 'x', 'A charge of $61.44 ending in 1111'), null, 'not an issuer: ignored');
});

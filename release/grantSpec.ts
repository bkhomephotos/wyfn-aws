// Payment grants and payment approvals: the one format shared by the site (which signs grants), the filing worker
// (which carries them) and the release function in AWS (which verifies them before it decrypts a card).
//
// THIS FILE IS COPIED BYTE FOR BYTE into wyfn-aws (release/grantSpec.ts). It imports nothing but node:crypto so it
// runs the same in a Netlify function and in Lambda. Change it in both places, with the shared test vectors.
//
// Grant   "wyfng1.<payload>.<signature>"   payload: base64url(JSON of GrantClaims); signature: Ed25519 over
//          "wyfn-pay-grant-v1\0" + payload, by the site's GRANT_SIGNING_KEY. Lives 5 minutes, used once (the release
//          function records its jti with a conditional write). Names one order, one Filing ID and report year, one
//          Wyoming invoice, one exact amount, one card slot, one attempt, one worker and lease generation.
// Approval  BK's passkey (WebAuthn) signature over the SHA-256 of one ApprovalPayload. The release function checks
//          it against BK's public keys as stored in AWS, so nothing that only reaches the site (a stolen session, a
//          PIN read from BK's email, a forged request) can approve a payment. Limit: a passkey prompt does not show
//          what is being signed, so a site whose code was taken over could present an approval's challenge as an
//          ordinary sign-in and get it signed. The release function's own caps (per hour, per day, approvals used
//          once) bound that case; a passkey kept only for approvals (a hardware key) makes an unexpected prompt visible.

import { createHash, createPublicKey, sign as edSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';

export const GRANT_PREFIX = 'wyfng1';
export const GRANT_DOMAIN = 'wyfn-pay-grant-v1\0';
export const APPROVAL_DOMAIN = 'wyfn-pay-approval-v1\0';
/** A grant never lives longer than this. */
export const GRANT_MAX_LIFE_S = 300;
/** Leeway for clocks that differ a little between Netlify, the worker and Lambda. */
export const CLOCK_SKEW_S = 30;

export type Slot = 'debit' | 'chase';

export interface ApprovalPayload {
  v: 1;
  typ: 'wyfn-pay-approval';
  id: string;
  ref: string;
  filingId: string;
  reportYear: number;
  stateFeeCents: number;
  processingFeeCents: number;
  totalCents: number;
  attempt: number;
  scope: 'exception' | 'attended';
  /** unix seconds */
  iat: number;
  exp: number;
}

/** A WebAuthn assertion, each part base64url as the browser returned it. */
export interface PasskeyAssertion {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

export interface SignedApproval {
  payload: ApprovalPayload;
  assertion: PasskeyAssertion;
}

export interface GrantClaims {
  v: 1;
  typ: 'wyfn-pay-grant';
  jti: string;
  ref: string;
  filingId: string;
  reportYear: number;
  invoice: string;
  amountCents: number;
  stateFeeCents: number;
  processingFeeCents: number;
  slot: Slot;
  attempt: number;
  workerId: string;
  generation: number;
  authority: 'automatic' | 'approval';
  /** BK's signed approval, required when authority is 'approval'. */
  approval: SignedApproval | null;
  mode: 'live' | 'test';
  iat: number;
  exp: number;
}

const b64u = (b: Buffer | Uint8Array | string) => Buffer.from(b).toString('base64url');
const fromB64u = (s: string) => Buffer.from(s, 'base64url');

/** JSON with keys sorted at every level and no spaces: the exact bytes that are hashed or signed. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value as Record<string, unknown>).filter((k) => (value as Record<string, unknown>)[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`).join(',')}}`;
}

/** The WebAuthn challenge BK's passkey signs for one approval: base64url(SHA-256(domain + canonical payload)). */
export function approvalChallenge(p: ApprovalPayload): string {
  return b64u(createHash('sha256').update(APPROVAL_DOMAIN).update(canonicalJson(p)).digest());
}

export function signGrant(claims: GrantClaims, privateKey: KeyObject): string {
  const payload = b64u(canonicalJson(claims));
  const sig = edSign(null, Buffer.from(GRANT_DOMAIN + payload), privateKey);
  return `${GRANT_PREFIX}.${payload}.${b64u(sig)}`;
}

export type GrantCheck = { ok: true; claims: GrantClaims } | { ok: false; why: string };

const JTI_RE = /^[A-Za-z0-9_-]{22}$/;
const REF_RE = /^WY-[2-9A-HJ-NP-Z]{8}$/;
const FILING_RE = /^\d{4}-\d{9}$/;
const INVOICE_RE = /^\d{20,96}$/;

/** Signature, shape and time only. Single use, caps and approval are the caller's (the release function's) to check. */
export function verifyGrant(token: unknown, publicKey: KeyObject, nowS: number): GrantCheck {
  if (typeof token !== 'string' || token.length > 8_000) return { ok: false, why: 'not a grant' };
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== GRANT_PREFIX) return { ok: false, why: 'not a grant' };
  const [, payload, sig] = parts;
  let good = false;
  try {
    good = cryptoVerify(null, Buffer.from(GRANT_DOMAIN + payload), publicKey, fromB64u(sig));
  } catch {
    good = false;
  }
  if (!good) return { ok: false, why: 'bad signature' };
  let c: GrantClaims;
  try {
    c = JSON.parse(fromB64u(payload).toString('utf8')) as GrantClaims;
  } catch {
    return { ok: false, why: 'unreadable claims' };
  }
  // The signed bytes must be the canonical form, so no two encodings of one grant exist.
  if (b64u(canonicalJson(c)) !== payload) return { ok: false, why: 'non-canonical claims' };
  const problem = claimsProblem(c);
  if (problem) return { ok: false, why: problem };
  if (c.exp - c.iat > GRANT_MAX_LIFE_S) return { ok: false, why: 'grant lives too long' };
  if (c.iat > nowS + CLOCK_SKEW_S) return { ok: false, why: 'grant issued in the future' };
  if (c.exp <= nowS) return { ok: false, why: 'grant expired' };
  return { ok: true, claims: c };
}

function claimsProblem(c: GrantClaims): string | null {
  if (c.v !== 1 || c.typ !== 'wyfn-pay-grant') return 'wrong grant type';
  if (!JTI_RE.test(c.jti)) return 'bad jti';
  if (!REF_RE.test(c.ref)) return 'bad order reference';
  if (!FILING_RE.test(c.filingId)) return 'bad Filing ID';
  if (!Number.isInteger(c.reportYear) || c.reportYear < 2000 || c.reportYear > 2100) return 'bad report year';
  if (!INVOICE_RE.test(c.invoice)) return 'bad invoice';
  for (const n of [c.amountCents, c.stateFeeCents, c.processingFeeCents]) if (!Number.isInteger(n) || n <= 0) return 'bad amount';
  if (c.stateFeeCents + c.processingFeeCents !== c.amountCents) return 'amount is not fee plus card fee';
  if (c.slot !== 'debit' && c.slot !== 'chase') return 'bad slot';
  if (!Number.isInteger(c.attempt) || c.attempt < 1 || c.attempt > 4) return 'bad attempt';
  if (typeof c.workerId !== 'string' || !/^[a-z0-9-]{1,64}$/.test(c.workerId)) return 'bad worker';
  if (!Number.isInteger(c.generation) || c.generation < 1) return 'bad generation';
  if (c.authority !== 'automatic' && c.authority !== 'approval') return 'bad authority';
  if (c.authority === 'approval' && !c.approval) return 'approval missing';
  if (c.authority === 'automatic' && c.approval) return 'unexpected approval';
  if (c.mode !== 'live' && c.mode !== 'test') return 'bad mode';
  if (!Number.isInteger(c.iat) || !Number.isInteger(c.exp)) return 'bad times';
  return null;
}

/** Does the signed approval authorize exactly this grant? null = yes. (The passkey signature is checked separately.) */
export function approvalMatchesGrant(c: GrantClaims, nowS: number): string | null {
  const a = c.approval?.payload;
  if (!a) return 'no approval';
  if (a.v !== 1 || a.typ !== 'wyfn-pay-approval') return 'wrong approval type';
  if (a.ref !== c.ref || a.filingId !== c.filingId || a.reportYear !== c.reportYear) return 'approval is for another filing';
  if (a.attempt !== c.attempt) return 'approval is for another attempt';
  if (a.totalCents !== c.amountCents || a.stateFeeCents !== c.stateFeeCents || a.processingFeeCents !== c.processingFeeCents) return 'approval is for another amount';
  if (a.exp <= nowS) return 'approval expired';
  if (a.iat > nowS + CLOCK_SKEW_S) return 'approval issued in the future';
  return null;
}

export interface PasskeyKey {
  credentialId: string;
  /** SPKI DER, base64. ES256 (P-256), Ed25519, or RS256 (RSA, 2048 bits or more: Windows Hello). */
  spki: string;
}

/**
 * Checks BK's WebAuthn assertion over an approval: the challenge is this approval's, the origin and relying party are
 * the dashboard's, the user was present AND verified (PIN or biometric on the key), and the signature verifies with a
 * registered key. Pure: no counters (the release function's ledger keeps approval ids single-use).
 */
export function verifyPasskeyApproval(
  approval: SignedApproval,
  keys: PasskeyKey[],
  expect: { origin: string; rpId: string },
): string | null {
  const a = approval.assertion;
  const key = keys.find((k) => k.credentialId === a.credentialId);
  if (!key) return 'unknown passkey';
  let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  const clientBytes = fromB64u(a.clientDataJSON);
  try {
    client = JSON.parse(clientBytes.toString('utf8'));
  } catch {
    return 'unreadable client data';
  }
  if (!client || typeof client !== 'object') return 'unreadable client data';
  if (client.type !== 'webauthn.get') return 'not an assertion';
  if (client.challenge !== approvalChallenge(approval.payload)) return 'challenge is not this approval';
  if (client.origin !== expect.origin) return 'wrong origin';
  if (client.crossOrigin === true) return 'cross-origin assertion';
  const auth = fromB64u(a.authenticatorData);
  if (auth.length < 37) return 'short authenticator data';
  const rpHash = createHash('sha256').update(expect.rpId).digest();
  if (!auth.subarray(0, 32).equals(rpHash)) return 'wrong relying party';
  const flags = auth[32];
  if ((flags & 0x01) === 0) return 'user not present';
  if ((flags & 0x04) === 0) return 'user not verified';
  const signed = Buffer.concat([auth, createHash('sha256').update(clientBytes).digest()]);
  let pub: KeyObject;
  try {
    pub = createPublicKey({ key: Buffer.from(key.spki, 'base64'), format: 'der', type: 'spki' });
  } catch {
    return 'bad registered key';
  }
  const sig = fromB64u(a.signature);
  let good = false;
  try {
    if (pub.asymmetricKeyType === 'ed25519') good = cryptoVerify(null, signed, pub, sig);
    else if (pub.asymmetricKeyType === 'ec' && pub.asymmetricKeyDetails?.namedCurve === 'prime256v1') good = cryptoVerify('sha256', signed, { key: pub, dsaEncoding: 'der' }, sig);
    else if (pub.asymmetricKeyType === 'rsa' && (pub.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048) good = cryptoVerify('sha256', signed, pub, sig); // RS256: PKCS#1 v1.5
    else return 'unsupported key type';
  } catch {
    good = false;
  }
  return good ? null : 'bad passkey signature';
}

import { createPublicKey } from 'node:crypto';
import { decide, type Ledger, type ReleaseConfig } from './decide';
import type { PasskeyKey, Slot } from './grantSpec';

// The release function's Lambda handler. Invoked only by the worker's instance role (the function's resource
// policy), through the VPC's Lambda endpoint (whose endpoint policy allows only this function). The AWS SDK v3 that
// ships with the Node.js 22 Lambda runtime is used; nothing is bundled but this code.
//
//   in   { grant: "wyfng1.…" }
//   out  { ok: true, card: { number, expMonth, expYear, cvv, name, street, zip } } | { ok: false, why }
//
// Logs: one line per decision with the grant's order reference, slot, amount and a jti prefix. Never a card value,
// never the grant itself. The card secret is decrypted with the card KMS key, which only this function's role may
// use; CloudTrail alarms on any other principal's decrypt.

interface CardSecret {
  number: string;
  expMonth: string;
  expYear: string;
  cvv?: string | null;
  name: string;
  street: string;
  zip: string;
}

const TABLE = process.env.LEDGER_TABLE ?? 'wyfn-release';

async function aws() {
  // Present in the Lambda runtime; imported lazily so tests of decide.ts never need them.
  const ddb = await import('@aws-sdk/client-dynamodb' as string);
  const sm = await import('@aws-sdk/client-secrets-manager' as string);
  const kms = await import('@aws-sdk/client-kms' as string);
  return { ddb, sm, kms };
}

async function loadConfig(db: { send: (c: unknown) => Promise<unknown> }, ddb: Record<string, new (x: unknown) => unknown>): Promise<ReleaseConfig> {
  const out = (await db.send(new ddb.GetItemCommand({ TableName: TABLE, Key: { pk: { S: 'config' } }, ConsistentRead: true }))) as { Item?: { body?: { S?: string } } };
  const raw = JSON.parse(out.Item?.body?.S ?? 'null') as {
    killSwitch: boolean; attended: boolean; normalMaxCents: number; perHour: number; perDayCents: number; hours: { start: string; end: string } | null;
    slots: Record<Slot, { enabled: boolean }>; acceptTestGrants: boolean; sitePublicKeySpki: string; passkeys: PasskeyKey[]; rp: { origin: string; rpId: string };
  } | null;
  if (!raw) throw new Error('no release config');
  return { ...raw, sitePublicKey: createPublicKey({ key: Buffer.from(raw.sitePublicKeySpki, 'base64'), format: 'der', type: 'spki' }) };
}

function dynamoLedger(db: { send: (c: unknown) => Promise<unknown> }, ddb: Record<string, new (x: unknown) => unknown>): Ledger {
  return {
    async record(r) {
      const items: unknown[] = [
        { Put: { TableName: TABLE, Item: { pk: { S: `jti#${r.jti}` }, ref: { S: r.ref }, slot: { S: r.slot }, cents: { N: String(r.amountCents) }, at: { S: r.at } }, ConditionExpression: 'attribute_not_exists(pk)' } },
        { Update: { TableName: TABLE, Key: { pk: { S: `hour#${r.hourKey}` } }, UpdateExpression: 'ADD n :one', ConditionExpression: 'attribute_not_exists(n) OR n < :max', ExpressionAttributeValues: { ':one': { N: '1' }, ':max': { N: String(r.perHour) } } } },
        { Update: { TableName: TABLE, Key: { pk: { S: `day#${r.dayKey}` } }, UpdateExpression: 'ADD cents :c', ConditionExpression: 'attribute_not_exists(cents) OR cents <= :room', ExpressionAttributeValues: { ':c': { N: String(r.amountCents) }, ':room': { N: String(r.perDayCents - r.amountCents) } } } },
        // The release log the alert parser matches card alerts against, independently of the site.
        { Put: { TableName: TABLE, Item: { pk: { S: `release#${r.at}#${r.jti.slice(0, 8)}` }, gsi: { S: 'release' }, slot: { S: r.slot }, cents: { N: String(r.amountCents) }, at: { S: r.at }, ref: { S: r.ref } } } },
      ];
      if (r.approvalId) items.push({ Put: { TableName: TABLE, Item: { pk: { S: `approval#${r.approvalId}` }, at: { S: r.at } }, ConditionExpression: 'attribute_not_exists(pk)' } });
      if (r.perDayCents - r.amountCents < 0) return { ok: false, why: 'daily limit reached' };
      try {
        await db.send(new ddb.TransactWriteItemsCommand({ TransactItems: items }));
        return { ok: true };
      } catch (err) {
        const reasons = (err as { CancellationReasons?: { Code?: string }[] }).CancellationReasons?.map((x) => x.Code) ?? [];
        const which = ['grant already used', 'hourly limit reached', 'daily limit reached', 'release log', 'approval already used'];
        const i = reasons.findIndex((c) => c === 'ConditionalCheckFailed');
        return { ok: false, why: i >= 0 ? which[i] : 'ledger write failed' };
      }
    },
  };
}

export async function handler(event: { grant?: unknown }): Promise<{ ok: boolean; why?: string; card?: CardSecret }> {
  const { ddb, sm } = await aws();
  const db = new ddb.DynamoDBClient({}) as { send: (c: unknown) => Promise<unknown> };
  let decision;
  try {
    decision = await decide(event?.grant, await loadConfig(db, ddb), dynamoLedger(db, ddb), new Date());
  } catch (err) {
    console.log(JSON.stringify({ decision: 'refused', why: 'release function error', error: err instanceof Error ? err.name : 'error' }));
    return { ok: false, why: 'release function error' };
  }
  if (!decision.ok) {
    console.log(JSON.stringify({ decision: 'refused', why: decision.why }));
    return { ok: false, why: decision.why };
  }
  const g = decision.claims;
  const secrets = new sm.SecretsManagerClient({}) as { send: (c: unknown) => Promise<{ SecretString?: string }> };
  const secret = await secrets.send(new sm.GetSecretValueCommand({ SecretId: `wyfn/card/${g.slot}` }));
  const card = JSON.parse(secret.SecretString ?? '{}') as CardSecret;
  if (!card.cvv) card.cvv = await sessionCvv(db, ddb, g.slot);
  console.log(JSON.stringify({ decision: 'released', ref: g.ref, slot: g.slot, cents: g.amountCents, attempt: g.attempt, jti: g.jti.slice(0, 6), authority: g.authority }));
  return { ok: true, card };
}

/**
 * The attended pilot's security code, when the card's secret holds none: BK enters it for a session with
 * scripts/card-session.sh. It is stored KMS-encrypted with an expiry and is useless after it; no expiry, no code.
 */
async function sessionCvv(db: { send: (c: unknown) => Promise<unknown> }, ddb: Record<string, new (x: unknown) => unknown>, slot: Slot): Promise<string | null> {
  const { kms } = await aws();
  const out = (await db.send(new ddb.GetItemCommand({ TableName: TABLE, Key: { pk: { S: `cvv#${slot}` } }, ConsistentRead: true }))) as { Item?: { blob?: { B?: Uint8Array }; expiresAt?: { N?: string } } };
  const exp = Number(out.Item?.expiresAt?.N ?? 0);
  if (!out.Item?.blob?.B || exp * 1000 <= Date.now()) return null;
  const client = new kms.KMSClient({}) as { send: (c: unknown) => Promise<{ Plaintext?: Uint8Array }> };
  const plain = await client.send(new kms.DecryptCommand({ CiphertextBlob: out.Item.blob.B, EncryptionContext: { purpose: 'wyfn-cvv-session', slot } }));
  return plain.Plaintext ? Buffer.from(plain.Plaintext).toString('utf8') : null;
}

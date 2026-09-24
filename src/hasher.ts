import { PBKDF2 } from './config';
import type { Env } from './env';
import { b64uToBytes, bytesToB64u, concatBytes, jsonResponse, TE } from './util';

const DUMMY_SALT = 'A'.repeat(22);
const DUMMY_DERIVED = 'A'.repeat(43);
const DUMMY_PHC = `$pbkdf2$sha256$i=${PBKDF2.iterations}$r=${PBKDF2.rounds}$${DUMMY_SALT}$${DUMMY_DERIVED}`;

function parsePhc(phc: string): { iterations: number; rounds: number; salt: Uint8Array; derived: Uint8Array } | null {
  const m = /^\$pbkdf2\$sha256\$i=(\d+)\$r=(\d+)\$(.+)\$(.+)$/.exec(phc);
  if (!m) return null;
  const iterations = Number(m[1]);
  const rounds = Number(m[2]);
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 100000) return null;
  if (!Number.isSafeInteger(rounds) || rounds < 1 || rounds > 16) return null;
  const salt = b64uToBytes(m[3]);
  const derived = b64uToBytes(m[4]);
  if (salt.length !== PBKDF2.saltLenBytes || derived.length !== PBKDF2.keyLenBytes) return null;
  return { iterations, rounds, salt, derived };
}

async function derive(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    PBKDF2.keyLenBytes * 8,
  );
  return new Uint8Array(bits);
}

async function deriveRounds(password: string, salt: Uint8Array, iterations: number, rounds: number): Promise<Uint8Array> {
  let input: Uint8Array = TE.encode(password);
  let out: Uint8Array = new Uint8Array(0);
  for (let r = 0; r < rounds; r++) {
    out = await derive(input, salt, iterations);
    input = out;
  }
  return out;
}

function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  let d = a.length ^ b.length;
  for (let i = 0; i < a.length && i < b.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function saltInput(pepper: string, salt: Uint8Array): Uint8Array {
  return concatBytes(TE.encode(pepper), salt);
}

export async function hashPasswordToPhc(password: string, pepper: string): Promise<string> {
  const salt = new Uint8Array(PBKDF2.saltLenBytes);
  crypto.getRandomValues(salt);
  const derived = await deriveRounds(password, saltInput(pepper, salt), PBKDF2.iterations, PBKDF2.rounds);
  return `$pbkdf2$sha256$i=${PBKDF2.iterations}$r=${PBKDF2.rounds}$${bytesToB64u(salt)}$${bytesToB64u(derived)}`;
}

export async function verifyPhc(password: string, phc: string, pepper: string): Promise<boolean> {
  const parsed = parsePhc(phc);
  if (!parsed) return false;
  const derived = await deriveRounds(password, saltInput(pepper, parsed.salt), parsed.iterations, parsed.rounds);
  return ctEqual(derived, parsed.derived);
}

export class Hasher {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const body = (await request.json()) as { op?: 'hash' | 'verify'; password?: string; phc?: string };
    const pepper = this.env.PEPPER ?? '';
    if (body.op === 'hash' && typeof body.password === 'string') {
      return jsonResponse({ phc: await hashPasswordToPhc(body.password, pepper) });
    }
    if (body.op === 'verify' && typeof body.password === 'string' && typeof body.phc === 'string') {
      return jsonResponse({ ok: await verifyPhc(body.password, body.phc, pepper) });
    }
    return jsonResponse({ error: 'bad request' }, 400);
  }
}

export async function doHash(env: Env, password: string, shard: string): Promise<string> {
  const stub = env.HASHER.get(env.HASHER.idFromName('h:' + shard));
  const res = await stub.fetch('https://internal/hash', {
    method: 'POST',
    body: JSON.stringify({ op: 'hash', password }),
  });
  const j = (await res.json()) as { phc?: string };
  if (!j.phc) throw new Error('hash failed');
  return j.phc;
}

export async function doVerify(env: Env, password: string, phc: string, shard: string): Promise<boolean> {
  const stub = env.HASHER.get(env.HASHER.idFromName('h:' + shard));
  const res = await stub.fetch('https://internal/verify', {
    method: 'POST',
    body: JSON.stringify({ op: 'verify', password, phc }),
  });
  const j = (await res.json()) as { ok?: boolean };
  return j.ok === true;
}

export function dummyPhc(): string {
  return DUMMY_PHC;
}
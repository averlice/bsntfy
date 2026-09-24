import { randomBytes } from '@noble/hashes/utils';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const HEX = '0123456789abcdef';

export const TE = new TextEncoder();
export const TD = new TextDecoder();

export function bytesToB64u(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const rem = bytes.length - i;
    const b0 = bytes[i];
    const b1 = rem > 1 ? bytes[i + 1] : 0;
    const b2 = rem > 2 ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    if (rem === 1) break;
    s += B64[(n >> 6) & 63];
    if (rem === 2) break;
    s += B64[n & 63];
  }
  return s.replace(/\+/g, '-').replace(/\//g, '_');
}

export function b64uToBytes(s: string): Uint8Array {
  const clean = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = clean.length % 4 ? '='.repeat(4 - (clean.length % 4)) : '';
  const bin = atob(clean + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
  return s;
}

export function hexToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function concatBytes(...lists: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const l of lists) len += l.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const l of lists) {
    out.set(l, o);
    o += l.length;
  }
  return out;
}

export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

export function randomBytesN(n = 32): Uint8Array {
  return randomBytes(n);
}

export function randToken(prefix: string, n = 32): string {
  return prefix + bytesToB64u(randomBytesN(n));
}

export function randomInt(min: number, max: number): number {
  const range = max - min;
  const bytes = randomBytes(4);
  const v = new DataView(bytes.buffer).getUint32(0, true);
  return min + (v % range);
}

export async function sha256Digest(data: string | Uint8Array): Promise<Uint8Array> {
  const buf = typeof data === 'string' ? TE.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  return bytesToHex(await sha256Digest(data));
}

export function randomAccountNumber(len = 10): string {
  let n = randomInt(0, 10 ** len);
  if (String(n).length < len) n = randomInt(0, 10 ** (len - 1)) + 10 ** (len - 1);
  return String(n).padStart(len, '0');
}

export function validateAccountNumber(n: unknown): string | null {
  if (typeof n !== 'string') return null;
  const s = n.trim();
  return /^\d{10}$/.test(s) ? s : null;
}

export function validateTopicName(n: unknown): string | null {
  if (typeof n !== 'string') return null;
  const s = n.toLowerCase();
  return /^[a-z0-9][a-z0-9_-]{1,31}$/.test(s) ? s : null;
}

export function validatePassword(p: unknown): string | null {
  if (typeof p !== 'string') return null;
  const len = TE.encode(p).length;
  if (len < 12 || len > 128) return null;
  return p;
}

export function clientIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP') ?? '';
}

export function applySecurityHeaders(headers: Headers): void {
  if (!headers.has('Strict-Transport-Security')) headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  if (!headers.has('X-Content-Type-Options')) headers.set('X-Content-Type-Options', 'nosniff');
  if (!headers.has('X-Frame-Options')) headers.set('X-Frame-Options', 'DENY');
  if (!headers.has('Referrer-Policy')) headers.set('Referrer-Policy', 'no-referrer');
  if (!headers.has('Content-Security-Policy')) headers.set('Content-Security-Policy', "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  if (!headers.has('Cache-Control')) headers.set('Cache-Control', 'no-store');
}

export function secureResponse(body: BodyInit | null, init?: ResponseInit): Response {
  const res = new Response(body, init);
  applySecurityHeaders(res.headers);
  return res;
}

export function jsonResponse(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return secureResponse(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });
}

export function error(status: number, message: string, headers: Record<string, string> = {}): Response {
  return jsonResponse({ error: message }, status, headers);
}

export async function readJson<T>(request: Request, maxBytes = 16 * 1024): Promise<T | null> {
  try {
    const buf = await request.arrayBuffer();
    if (buf.byteLength > maxBytes) return null;
    return JSON.parse(TD.decode(buf)) as T;
  } catch {
    return null;
  }
}

export async function checkSoftLimit(env: { KEYS: KVNamespace }, bucket: string, limit: number, windowS: number): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  const key = `rl:${bucket}:${Math.floor(now / windowS)}`;
  const current = Number((await env.KEYS.get(key)) ?? '0') + 1;
  await env.KEYS.put(key, String(current), { expirationTtl: windowS });
  return current <= limit;
}

export async function getIndex<T>(kv: KVNamespace, key: string): Promise<T[]> {
  const raw = await kv.get(key);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}

export async function indexAdd<T>(kv: KVNamespace, key: string, entry: T, max = 1000): Promise<void> {
  const arr = await getIndex<T>(kv, key);
  arr.unshift(entry);
  if (arr.length > max) arr.length = max;
  await kv.put(key, JSON.stringify(arr));
}

export async function indexRemove<T>(kv: KVNamespace, key: string, predicate: (t: T) => boolean): Promise<void> {
  const arr = await getIndex<T>(kv, key);
  const next = arr.filter((t) => !predicate(t));
  if (next.length !== arr.length) await kv.put(key, JSON.stringify(next));
}
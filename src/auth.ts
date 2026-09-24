import { SESSION_COOKIE, SESSION_TTL_S } from './config';
import type { DeviceScope, DeviceTokenRecord, Env, KeyRecord, SessRecord } from './env';
import { apikeyKey, dtokKey, sessIdxKey, sessKey } from './kvkeys';
import { bytesToB64u, getIndex, indexAdd, indexRemove, randomBytesN, sha256Hex, jsonResponse } from './util';

export interface Principal {
  acct: string;
  kind: 'session' | 'device';
  scope: DeviceScope | null;
  deviceId?: string;
}

export function cookieFrom(token: string): string {
  const maxAge = SESSION_TTL_S;
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function bearerToken(request: Request): string | null {
  const auth = request.headers.get('Authorization');
  if (auth && auth.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
  return null;
}

function credentialString(request: Request): string | null {
  const b = bearerToken(request);
  if (b) return b;
  const apiKey = request.headers.get('X-API-Key');
  if (apiKey) return apiKey;
  return request.headers.get('X-Device-Token');
}

function sessionFromCookieHeader(request: Request): string | null {
  const cookie = request.headers.get('cookie');
  if (!cookie) return null;
  for (const part of cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(SESSION_COOKIE + '=')) return trimmed.slice(SESSION_COOKIE.length + 1);
  }
  return null;
}

export async function getSessionAcct(request: Request, env: Env): Promise<string | null> {
  const token = sessionFromCookieHeader(request);
  if (!token) return null;
  const rec = await env.SESSIONS.get<SessRecord>(sessKey(await sha256Hex(token)), 'json');
  return rec?.acct ?? null;
}

export async function getApiKeyRecord(request: Request, env: Env): Promise<KeyRecord | null> {
  const cred = credentialString(request);
  if (!cred || !cred.startsWith('fy_')) return null;
  const rec = await env.KEYS.get<KeyRecord>(apikeyKey(await sha256Hex(cred)), 'json');
  return rec ?? null;
}

export async function getDeviceTokenRecord(request: Request, env: Env): Promise<DeviceTokenRecord | null> {
  const cred = credentialString(request);
  if (!cred || !cred.startsWith('fyd_')) return null;
  const rec = await env.KEYS.get<DeviceTokenRecord>(dtokKey(await sha256Hex(cred)), 'json');
  if (rec && rec.expiresAt && Date.now() > rec.expiresAt) return null;
  return rec ?? null;
}

export async function getPrincipal(request: Request, env: Env): Promise<Principal | null> {
  const b = bearerToken(request);
  if (b) {
    if (b.startsWith('fyd_')) {
      const rec = await getDeviceTokenRecord(request, env);
      return rec ? { acct: rec.acct, kind: 'device', scope: rec.scope, deviceId: rec.id } : null;
    }
    if (b.startsWith('fy_')) return null; // API keys authorize topics, not management
    const rec = await env.SESSIONS.get<SessRecord>(sessKey(await sha256Hex(b)), 'json');
    return rec ? { acct: rec.acct, kind: 'session', scope: null } : null;
  }
  const token = sessionFromCookieHeader(request);
  if (!token) return null;
  const rec = await env.SESSIONS.get<SessRecord>(sessKey(await sha256Hex(token)), 'json');
  return rec ? { acct: rec.acct, kind: 'session', scope: null } : null;
}

export function canManage(p: Principal | null): boolean {
  return Boolean(p && (p.kind === 'session' || (p.kind === 'device' && p.scope === 'manage')));
}

export async function createSession(env: Env, acct: string): Promise<{ token: string; cookie: string }> {
  const token = bytesToB64u(randomBytesN(32));
  const rec: SessRecord = { acct, created: Date.now() };
  const sha = await sha256Hex(token);
  await env.SESSIONS.put(sessKey(sha), JSON.stringify(rec), { expirationTtl: SESSION_TTL_S });
  await indexAdd<string>(env.SESSIONS, sessIdxKey(acct), sha, 50);
  return { token, cookie: cookieFrom(token) };
}

export async function destroySession(request: Request, env: Env): Promise<number> {
  let token = sessionFromCookieHeader(request);
  if (!token) {
    const b = bearerToken(request);
    if (b && !b.startsWith('fy_') && !b.startsWith('fyd_')) token = b;
  }
  if (!token) return 0;
  const sha = await sha256Hex(token);
  const rec = await env.SESSIONS.get<SessRecord>(sessKey(sha), 'json');
  await env.SESSIONS.delete(sessKey(sha));
  if (rec) await indexRemove<string>(env.SESSIONS, sessIdxKey(rec.acct), (id) => id === sha);
  return 1;
}

export async function destroyAllSessions(env: Env, acct: string): Promise<void> {
  const ids = await getIndex<string>(env.SESSIONS, sessIdxKey(acct));
  for (const sha of ids) await env.SESSIONS.delete(sessKey(sha));
  await env.SESSIONS.delete(sessIdxKey(acct));
}

export function unauthorized(): Response {
  return jsonResponse({ error: 'unauthorized' }, 401);
}
import { DEVICE_TOKEN_TTL_S, MAX_DEVICE_TOKENS, PAIR_CODE_FAILS, PAIR_CODE_TTL_S, PAIR_CODE_WINDOW_S, REGISTER_PER_IP_H, SESSION_COOKIE } from './config';
import type { AccountRecord, DeviceScope, DeviceTokenRecord, Env, KeyPerms, PairCodeRecord, SubRecord } from './env';
import { doHash, doVerify, dummyPhc } from './hasher';
import { acctKey, apikeyKey, apikeysIdxKey, dtokKey, dtoksIdxKey, feedKey, pairCodeActiveKey, pairCodeKey, subKey, subsIdxKey, topicKey, topicsIdxKey } from './kvkeys';
import { rateLimitOp } from './ratelimit';
import { createSession, destroyAllSessions, destroySession } from './auth';
import {
  checkSoftLimit,
  clientIp,
  error,
  getIndex,
  indexAdd,
  indexRemove,
  jsonResponse,
  randToken,
  randomAccountNumber,
  randomInt,
  readJson,
  sha256Hex,
  validateAccountNumber,
  validatePassword,
} from './util';

interface LoginBody {
  accountNumber?: unknown;
  password?: unknown;
}

interface RegisterBody {
  password?: unknown;
}

interface PasswordBody {
  oldPassword?: unknown;
  newPassword?: unknown;
}

function retryAfter(r: { banned: boolean; retryAfterMs: number }): Response {
  return error(429, 'too many attempts; try again later', { 'Retry-After': String(Math.max(1, Math.ceil(r.retryAfterMs / 1000))) });
}

export async function handleRegister(request: Request, env: Env, ip: string): Promise<Response> {
  const body = await readJson<RegisterBody>(request);
  const password = validatePassword(body?.password);
  if (!password) return error(400, 'password must be a string of 12-128 bytes');

  const allowed = await checkSoftLimit(env, `reg:${ip}`, REGISTER_PER_IP_H, 3600);
  if (!allowed) return error(429, 'too many registrations from this address');

  const r = await rateLimitOp(env, ip, 'check');
  if (r.banned) return retryAfter(r);

  let acct = '';
  for (let i = 0; i < 10 && !acct; i++) {
    const candidate = randomAccountNumber();
    const exists = await env.ACCOUNTS.get(acctKey(candidate));
    if (!exists) acct = candidate;
  }
  if (!acct) return error(503, 'could not allocate an account number, try again');

  const phc = await doHash(env, password, acct);
  await env.ACCOUNTS.put(acctKey(acct), JSON.stringify({ acct, phc, created: Date.now() }));

  const session = await createSession(env, acct);
  return jsonResponse({ accountNumber: acct, session: session.token }, 201, { 'Set-Cookie': session.cookie });
}

export async function handleLogin(request: Request, env: Env, ip: string): Promise<Response> {
  const body = await readJson<LoginBody>(request);
  const acctNum = validateAccountNumber(body?.accountNumber);
  const password = typeof body?.password === 'string' ? body.password : null;

  const r = await rateLimitOp(env, ip, 'check');
  if (r.banned) return retryAfter(r);

  if (!acctNum || !password) {
    await rateLimitOp(env, ip, 'fail', acctNum ?? 'unknown');
    return error(401, 'invalid credentials');
  }

  const rec = await env.ACCOUNTS.get<{ acct: string; phc: string }>(acctKey(acctNum), 'json');
  const phc = rec?.phc ?? dummyPhc();
  const ok = await doVerify(env, password, phc, acctNum);
  if (!ok) {
    await rateLimitOp(env, ip, 'fail', acctNum);
    return error(401, 'invalid credentials');
  }

  await rateLimitOp(env, ip, 'success', acctNum);
  const session = await createSession(env, acctNum);
  return jsonResponse({ accountNumber: acctNum, session: session.token }, 200, { 'Set-Cookie': session.cookie });
}

export async function handleLogout(request: Request, env: Env): Promise<Response> {
  await destroySession(request, env);
  return jsonResponse({ ok: true }, 200, { 'Set-Cookie': 'fy_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
}

export async function handleAccountInfo(request: Request, env: Env, acct: string): Promise<Response> {
  const rec = await env.ACCOUNTS.get<{ acct: string; phc: string; created: number }>(acctKey(acct), 'json');
  if (!rec) return error(404, 'account not found');
  return jsonResponse({ accountNumber: rec.acct, created: rec.created });
}

export async function handlePasswordChange(request: Request, env: Env, acct: string): Promise<Response> {
  const body = await readJson<PasswordBody>(request);
  const newPassword = validatePassword(body?.newPassword);
  if (!newPassword) return error(400, 'new password must be a string of 12-128 bytes');

  const rec = await env.ACCOUNTS.get<{ acct: string; phc: string; created: number }>(acctKey(acct), 'json');
  if (!rec) return error(404, 'account not found');

  const oldPassword = typeof body?.oldPassword === 'string' ? body.oldPassword : null;
  if (!oldPassword) return error(400, 'old password required');
  const ok = await doVerify(env, oldPassword, rec.phc, acct);
  if (!ok) return error(403, 'old password is incorrect');

  const phc = await doHash(env, newPassword, acct);
  await env.ACCOUNTS.put(acctKey(acct), JSON.stringify({ ...rec, phc, created: rec.created }));

  const tokens = await getIndex<string>(env.KEYS, dtoksIdxKey(acct));
  for (const id of tokens) await env.KEYS.delete(dtokKey(id));
  await env.KEYS.put(dtoksIdxKey(acct), '[]');

  const session = await createSession(env, acct);
  return jsonResponse({ ok: true, session: session.token }, 200, { 'Set-Cookie': session.cookie });
}

export async function deleteTopicCascade(env: Env, acct: string, topic: string): Promise<void> {
  const subs = await getIndex<SubRecord>(env.TOPICS, subsIdxKey(acct, topic));
  for (const s of subs) await env.TOPICS.delete(subKey(acct, topic, s.id));
  await env.TOPICS.delete(subsIdxKey(acct, topic));

  const ids = await getIndex<string>(env.KEYS, apikeysIdxKey(acct, topic));
  for (const id of ids) await env.KEYS.delete(apikeyKey(id));
  await env.KEYS.delete(apikeysIdxKey(acct, topic));

  await env.TOPICS.delete(topicKey(acct, topic));
  await env.FEEDS.delete(feedKey(acct, topic));
}

export async function handleAccountDelete(request: Request, env: Env, acct: string): Promise<Response> {
  const body = await readJson<{ password?: unknown }>(request);
  const password = typeof body?.password === 'string' ? body.password : null;
  if (!password) return error(400, 'password required');

  const rec = await env.ACCOUNTS.get<AccountRecord>(acctKey(acct), 'json');
  if (!rec) return error(404, 'account not found');

  const ok = await doVerify(env, password, rec.phc, acct);
  if (!ok) {
    await rateLimitOp(env, clientIp(request), 'fail', acct);
    return error(401, 'invalid credentials');
  }
  await rateLimitOp(env, clientIp(request), 'success', acct);

  const names = await getIndex<string>(env.TOPICS, topicsIdxKey(acct));
  for (const name of names) await deleteTopicCascade(env, acct, name);
  await env.TOPICS.delete(topicsIdxKey(acct));

  const dtoks = await getIndex<string>(env.KEYS, dtoksIdxKey(acct));
  for (const id of dtoks) await env.KEYS.delete(dtokKey(id));
  await env.KEYS.delete(dtoksIdxKey(acct));

  await destroyAllSessions(env, acct);
  await env.ACCOUNTS.delete(acctKey(acct));

  return jsonResponse({ ok: true }, 200, { 'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });
}

export async function handleDeviceTokenCreate(request: Request, env: Env, acct: string): Promise<Response> {
  const existing = await getIndex<string>(env.KEYS, dtoksIdxKey(acct));
  if (existing.length >= MAX_DEVICE_TOKENS) return error(409, 'device token limit reached');

  const body = await readJson<{ label?: unknown; scope?: unknown }>(request);
  const label = typeof body?.label === 'string' ? body.label.slice(0, 60) : '';
  const scope: DeviceScope = body?.scope === 'manage' ? 'manage' : 'push';
  const token = randToken('fyd_', 32);
  const id = await sha256Hex(token);
  const created = Date.now();
  const expiresAt = created + DEVICE_TOKEN_TTL_S * 1000;
  const rec: DeviceTokenRecord = { id, acct, label, scope, created, expiresAt };
  await env.KEYS.put(dtokKey(id), JSON.stringify(rec), { expirationTtl: DEVICE_TOKEN_TTL_S });
  await indexAdd<string>(env.KEYS, dtoksIdxKey(acct), id, MAX_DEVICE_TOKENS);
  return jsonResponse({ token, id: id.slice(0, 12), scope, created, expiresAt }, 201);
}

export async function handleDeviceTokenList(env: Env, acct: string): Promise<Response> {
  const ids = await getIndex<string>(env.KEYS, dtoksIdxKey(acct));
  const out: { id: string; scope: DeviceScope; label: string; created: number; expiresAt: number }[] = [];
  const stale: string[] = [];
  for (const id of ids) {
    const rec = await env.KEYS.get<DeviceTokenRecord>(dtokKey(id), 'json');
    if (!rec || (rec.expiresAt && Date.now() > rec.expiresAt)) {
      stale.push(id);
      continue;
    }
    out.push({ id: rec.id.slice(0, 12), scope: rec.scope, label: rec.label ?? '', created: rec.created, expiresAt: rec.expiresAt });
  }
  if (stale.length) {
    for (const id of stale) await env.KEYS.delete(dtokKey(id));
    await env.KEYS.put(dtoksIdxKey(acct), JSON.stringify(ids.filter((id) => !stale.includes(id))));
  }
  return jsonResponse({ tokens: out });
}

export async function handleDeviceTokenDelete(request: Request, env: Env, acct: string, idParam: string): Promise<Response> {
  let full: string | null = null;
  const ids = await getIndex<string>(env.KEYS, dtoksIdxKey(acct));
  for (const id of ids) {
    if (id.slice(0, 12) === idParam || id === idParam) {
      full = id;
      break;
    }
  }
if (!full) return error(404, 'token not found');
  await env.KEYS.delete(dtokKey(full));
  await indexRemove<string>(env.KEYS, dtoksIdxKey(acct), (id) => id === full);
  return jsonResponse({ ok: true });
}

function pairCodeDigits(): string {
  let n = '';
  for (let i = 0; i < 6; i++) n += String(randomInt(0, 10));
  return n;
}

export async function handlePairCodeCreate(env: Env, acct: string): Promise<Response> {
  const prior = await env.KEYS.get(pairCodeActiveKey(acct));
  if (prior) await env.KEYS.delete(pairCodeKey(acct, prior));

  const code = pairCodeDigits();
  const hash = await sha256Hex(code);
  const created = Date.now();
  const expiresAt = created + PAIR_CODE_TTL_S * 1000;
  const rec: PairCodeRecord = { acct, hash, created, expiresAt };
  await env.KEYS.put(pairCodeKey(acct, hash), JSON.stringify(rec), { expirationTtl: PAIR_CODE_TTL_S });
  await env.KEYS.put(pairCodeActiveKey(acct), hash, { expirationTtl: PAIR_CODE_TTL_S });
  return jsonResponse({ code, expiresAt });
}

export async function handlePairCodeRedeem(request: Request, env: Env, ip: string): Promise<Response> {
  const ipOk = await checkSoftLimit(env, `pairip:${ip}`, PAIR_CODE_FAILS, PAIR_CODE_WINDOW_S);
  if (!ipOk) return error(429, 'too many pairing attempts, try again later');

  const body = await readJson<{ accountNumber?: unknown; code?: unknown }>(request);
  const acctNum = validateAccountNumber(body?.accountNumber);
  const code = typeof body?.code === 'string' ? body.code.trim() : null;
  if (!acctNum || !code) return error(400, 'accountNumber and code required');

  const acctOk = await checkSoftLimit(env, `pairacct:${acctNum}`, 5, PAIR_CODE_WINDOW_S);
  if (!acctOk) return error(429, 'too many pairing attempts for this account, try again later');

  const hash = await sha256Hex(code);
  const active = await env.KEYS.get(pairCodeActiveKey(acctNum));
  const rec = active && active === hash ? await env.KEYS.get<PairCodeRecord>(pairCodeKey(acctNum, hash), 'json') : null;
  if (!rec || Date.now() > rec.expiresAt) return error(401, 'invalid or expired code');

  await env.KEYS.delete(pairCodeKey(acctNum, hash));
  await env.KEYS.delete(pairCodeActiveKey(acctNum));
  const session = await createSession(env, acctNum);
  return jsonResponse({ accountNumber: acctNum, session: session.token });
}

export type Perms = KeyPerms;
export function isPerm(p: unknown): p is KeyPerms {
  return p === 'read' || p === 'write' || p === 'readwrite';
}

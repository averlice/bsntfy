import { describe, expect, it, beforeEach } from 'vitest';
import { cookieFrom, doRequest, testEnv } from './helpers';
import type { Env } from '../src/env';
import { acctKey, apikeyKey, dtoksIdxKey, feedKey, sessIdxKey, subKey, subsIdxKey, topicKey, topicsIdxKey } from '../src/kvkeys';
import { sha256Hex } from '../src/util';

const PASSWORD = 'correct horse battery staple';

function stubNet() {
  const calls: { url: string; headers: Headers; bodyBytes: Uint8Array }[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const u = typeof input === 'string' ? input : (input as Request).url;
    if (u.includes('dns-query')) {
      const type = new URL(u).searchParams.get('type');
      const ans = type === 'AAAA' ? [] : [{ type: 1, data: '34.17.4.8' }];
      return new Response(JSON.stringify({ Answer: ans }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const h = new Headers((init?.headers as HeadersInit) ?? {});
    const bb = init?.body instanceof Uint8Array ? init.body : new Uint8Array();
    calls.push({ url: u, headers: h, bodyBytes: bb });
    return new Response(null, { status: 201 });
  }) as typeof fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = orig;
    },
  };
}

describe('bs-notify API', () => {
  let env: Env;
  let cookie: string;
  let acct: string;

  beforeEach(() => {
    env = testEnv();
    cookie = '';
    acct = '';
  });

  async function register() {
    const res = await doRequest(env, 'POST', '/v1/register', { body: JSON.stringify({ password: PASSWORD }) });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { accountNumber: string };
    acct = body.accountNumber;
    cookie = cookieFrom(res);
  }

  it('registers an account and returns a session', async () => {
    const res = await doRequest(env, 'POST', '/v1/register', { body: JSON.stringify({ password: PASSWORD }) });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { accountNumber: string };
    expect(body.accountNumber).toMatch(/^\d{10}$/);
    expect(res.headers.get('Set-Cookie')).toContain('fy_session=');
    expect(res.headers.get('Set-Cookie')).toContain('HttpOnly');
    expect(res.headers.get('Set-Cookie')).toContain('SameSite=Strict');
  });

  it('rejects weak passwords', async () => {
    const weak = await doRequest(env, 'POST', '/v1/register', { body: JSON.stringify({ password: 'short' }) });
    expect(weak.status).toBe(400);
  });

  it('rejects unknown accounts with a generic error', async () => {
    const res = await doRequest(env, 'POST', '/v1/login', {
      body: JSON.stringify({ accountNumber: '9999999999', password: PASSWORD }),
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('invalid credentials');
  });

  it('locks an IP for 48h after 3 failed logins', async () => {
    await register();
    for (let i = 0; i < 3; i++) {
      const bad = await doRequest(env, 'POST', '/v1/login', {
        body: JSON.stringify({ accountNumber: acct, password: 'definitely-wrong-pw-1' }),
      });
      expect(bad.status).toBe(401);
    }
    const locked = await doRequest(env, 'POST', '/v1/login', {
      body: JSON.stringify({ accountNumber: acct, password: PASSWORD }),
    });
    expect(locked.status).toBe(429);
  });

  it('limits registrations per IP', async () => {
    const results: number[] = [];
    for (let i = 0; i < 6; i++) {
      const res = await doRequest(env, 'POST', '/v1/register', { body: JSON.stringify({ password: PASSWORD }) });
      results.push(res.status);
    }
    expect(results.filter((s) => s === 201)).toHaveLength(5);
    expect(results[5]).toBe(429);
  });

  it('runs the publish/lookup flow through topics and keys', async () => {
    await register();

    const create = await doRequest(env, 'POST', '/v1/topics', {
      headers: { cookie },
      body: JSON.stringify({ name: 'pizza' }),
    });
    expect(create.status).toBe(201);

    const keyRes = await doRequest(env, 'POST', '/v1/topics/pizza/keys', {
      headers: { cookie },
      body: JSON.stringify({ label: 'webhook', perms: 'write' }),
    });
    expect(keyRes.status).toBe(201);
    const { key } = (await keyRes.json()) as { key: string };
    expect(key.startsWith('fy_')).toBe(true);

    const pub = await doRequest(env, 'POST', '/v1/publish/pizza', {
      headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'text/plain' },
      body: 'pepperoni',
    });
    expect(pub.status).toBe(200);

    const over = await doRequest(env, 'POST', '/v1/publish/pizza', {
      headers: { Authorization: 'Bearer ' + key },
      body: 'x'.repeat(5000),
    });
    expect(over.status).toBe(413);

    const anon = await doRequest(env, 'POST', '/v1/publish/pizza', { body: 'nope' });
    expect(anon.status).toBe(401);

    const readKeyRes = await doRequest(env, 'POST', '/v1/topics/pizza/keys', {
      headers: { cookie },
      body: JSON.stringify({ label: 'reader', perms: 'read' }),
    });
    const rkey = ((await readKeyRes.json()) as { key: string }).key;

    const writeCannotRead = await doRequest(env, 'GET', '/v1/messages/pizza', {
      headers: { Authorization: 'Bearer ' + key },
    });
    expect(writeCannotRead.status).toBe(401);

    const msgs = await doRequest(env, 'GET', '/v1/messages/pizza', {
      headers: { Authorization: 'Bearer ' + rkey },
    });
    expect(msgs.status).toBe(200);
    const msgsBody = (await msgs.json()) as { messages: { body: string; id: string; time: number }[] };
    expect(msgsBody.messages).toHaveLength(1);
    expect(msgsBody.messages[0]!.body).toBe('pepperoni');

    const list = await doRequest(env, 'GET', '/v1/topics', { headers: { cookie } });
    expect(((await list.json()) as { topics: string[] }).topics).toContain('pizza');
  });

  it('subscribes a device token and delivers an encrypted push', async () => {
    await register();

    await doRequest(env, 'POST', '/v1/topics', { headers: { cookie }, body: JSON.stringify({ name: 'alerts' }) });

    const dtRes = await doRequest(env, 'POST', '/v1/device-tokens', {
      headers: { cookie },
      body: JSON.stringify({ label: 'phone' }),
    });
    expect(dtRes.status).toBe(201);
    const dt = ((await dtRes.json()) as { token: string }).token;
    expect(dt.startsWith('fyd_')).toBe(true);

    const net = stubNet();
    try {
      const endpoint = 'https://push.example.com/push/yXMiyi';
      const subRes = await doRequest(env, 'POST', '/v1/topics/alerts/subscribe', {
        headers: { Authorization: 'Bearer ' + dt },
        body: JSON.stringify({
          endpoint,
          keys: { p256dh: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4', auth: 'BTBZMqHH6r4Tts7J_aSIgg' },
        }),
      });
      expect(subRes.status).toBe(201);

      const keyRes = await doRequest(env, 'POST', '/v1/topics/alerts/keys', {
        headers: { cookie },
        body: JSON.stringify({ perms: 'write' }),
      });
      const key = ((await keyRes.json()) as { key: string }).key;

      const pub = await doRequest(env, 'POST', '/v1/publish/alerts', {
        headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'text/plain' },
        body: 'it worked',
      });
      expect(pub.status).toBe(200);

      expect(net.calls).toHaveLength(1);
      const call = net.calls[0]!;
      expect(call.url).toBe(endpoint);
      expect(call.headers.get('content-encoding')).toBe('aes128gcm');
      expect(call.headers.get('authorization') ?? '').toMatch(/^vapid t=/);
      expect(call.bodyBytes.length).toBeGreaterThan('it worked'.length);

      const subs = await doRequest(env, 'GET', '/v1/topics/alerts/subscribers', { headers: { cookie } });
      const subBody = (await subs.json()) as { subscribers: { encrypted: boolean }[] };
      expect(subBody.subscribers[0]!.encrypted).toBe(true);
    } finally {
      net.restore();
    }
  });

  it('rejects a subscribe to a private endpoint', async () => {
    await register();
    await doRequest(env, 'POST', '/v1/topics', { headers: { cookie }, body: JSON.stringify({ name: 'foo' }) });
    const dtRes = await doRequest(env, 'POST', '/v1/device-tokens', { headers: { cookie }, body: JSON.stringify({}) });
    const dt = ((await dtRes.json()) as { token: string }).token;

    const subRes = await doRequest(env, 'POST', '/v1/topics/foo/subscribe', {
      headers: { Authorization: 'Bearer ' + dt },
      body: JSON.stringify({ endpoint: 'http://localhost:8080/push' }),
    });
    expect(subRes.status).toBe(400);
  });

  it('deletes a topic and cascades its keys, subscribers, and feed', async () => {
    await register();

    await doRequest(env, 'POST', '/v1/topics', { headers: { cookie }, body: JSON.stringify({ name: 'doomed' }) });

    const keyRes = await doRequest(env, 'POST', '/v1/topics/doomed/keys', {
      headers: { cookie },
      body: JSON.stringify({ perms: 'write' }),
    });
    const key = ((await keyRes.json()) as { key: string }).key;

    const endpoint = 'https://push.example.com/push/delme';
    const subId = (await sha256Hex(endpoint)).slice(0, 16);

    const net = stubNet();
    try {
      const dtRes = await doRequest(env, 'POST', '/v1/device-tokens', { headers: { cookie }, body: JSON.stringify({}) });
      const dt = ((await dtRes.json()) as { token: string }).token;
      const subRes = await doRequest(env, 'POST', '/v1/topics/doomed/subscribe', {
        headers: { Authorization: 'Bearer ' + dt },
        body: JSON.stringify({ endpoint }),
      });
      expect(subRes.status).toBe(201);

      const pub = await doRequest(env, 'POST', '/v1/publish/doomed', {
        headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'text/plain' },
        body: 'so long',
      });
      expect(pub.status).toBe(200);

      const del = await doRequest(env, 'DELETE', '/v1/topics/doomed', { headers: { cookie } });
      expect(del.status).toBe(200);

      expect(await env.TOPICS.get(topicKey(acct, 'doomed'))).toBeNull();
      expect(await env.TOPICS.get(subsIdxKey(acct, 'doomed'))).toBeNull();
      expect(await env.TOPICS.get(subKey(acct, 'doomed', subId))).toBeNull();
      expect(await env.KEYS.get(apikeyKey(await sha256Hex(key)))).toBeNull();
      expect(await env.FEEDS.get(feedKey(acct, 'doomed'))).toBeNull();
    } finally {
      net.restore();
    }

    const list = await doRequest(env, 'GET', '/v1/topics', { headers: { cookie } });
    expect(((await list.json()) as { topics: string[] }).topics).not.toContain('doomed');

    const delAgain = await doRequest(env, 'DELETE', '/v1/topics/doomed', { headers: { cookie } });
    expect(delAgain.status).toBe(404);

    const pubGone = await doRequest(env, 'POST', '/v1/publish/doomed', {
      headers: { Authorization: 'Bearer ' + key },
      body: 'nope',
    });
    expect(pubGone.status).toBe(401);
  });

  it('lets the owner remove a single subscriber', async () => {
    await register();
    await doRequest(env, 'POST', '/v1/topics', { headers: { cookie }, body: JSON.stringify({ name: 'news' }) });

    const endpoint = 'https://push.example.com/push/rm';
    const subId = (await sha256Hex(endpoint)).slice(0, 16);

    const net = stubNet();
    try {
      const dtRes = await doRequest(env, 'POST', '/v1/device-tokens', { headers: { cookie }, body: JSON.stringify({}) });
      const dt = ((await dtRes.json()) as { token: string }).token;
      await doRequest(env, 'POST', '/v1/topics/news/subscribe', {
        headers: { Authorization: 'Bearer ' + dt },
        body: JSON.stringify({ endpoint }),
      });

      const del = await doRequest(env, 'DELETE', '/v1/topics/news/subscribers/' + subId, { headers: { cookie } });
      expect(del.status).toBe(200);
      expect(await env.TOPICS.get(subKey(acct, 'news', subId))).toBeNull();

      const subs = await doRequest(env, 'GET', '/v1/topics/news/subscribers', { headers: { cookie } });
      expect(((await subs.json()) as { subscribers: unknown[] }).subscribers).toHaveLength(0);

      const missing = await doRequest(env, 'DELETE', '/v1/topics/news/subscribers/' + subId, { headers: { cookie } });
      expect(missing.status).toBe(404);
    } finally {
      net.restore();
    }
  });

  it('deletes an account after password confirmation and kills all its sessions', async () => {
    await register();

    const loginRes = await doRequest(env, 'POST', '/v1/login', {
      body: JSON.stringify({ accountNumber: acct, password: PASSWORD }),
    });
    expect(loginRes.status).toBe(200);
    const cookieB = cookieFrom(loginRes);

    await doRequest(env, 'POST', '/v1/topics', { headers: { cookie }, body: JSON.stringify({ name: 'gone' }) });
    await doRequest(env, 'POST', '/v1/device-tokens', { headers: { cookie }, body: JSON.stringify({}) });

    const bad = await doRequest(env, 'DELETE', '/v1/account', {
      headers: { cookie },
      body: JSON.stringify({ password: 'wrong-password-12345' }),
    });
    expect(bad.status).toBe(401);

    const still = await doRequest(env, 'GET', '/v1/account', { headers: { cookie } });
    expect(still.status).toBe(200);

    const del = await doRequest(env, 'DELETE', '/v1/account', {
      headers: { cookie },
      body: JSON.stringify({ password: PASSWORD }),
    });
    expect(del.status).toBe(200);

    expect(await env.ACCOUNTS.get(acctKey(acct))).toBeNull();
    expect(await env.SESSIONS.get(sessIdxKey(acct))).toBeNull();
    expect(await env.TOPICS.get(topicsIdxKey(acct))).toBeNull();
    expect(await env.TOPICS.get(topicKey(acct, 'gone'))).toBeNull();
    expect(await env.KEYS.get(dtoksIdxKey(acct))).toBeNull();

    for (const c of [cookie, cookieB]) {
      const after = await doRequest(env, 'GET', '/v1/account', { headers: { cookie: c } });
      expect(after.status).toBe(401);
    }

    const login = await doRequest(env, 'POST', '/v1/login', {
      body: JSON.stringify({ accountNumber: acct, password: PASSWORD }),
    });
    expect(login.status).toBe(401);
  });

  it('does not let a stale session create topics after account deletion', async () => {
    await register();
    const loginRes = await doRequest(env, 'POST', '/v1/login', {
      body: JSON.stringify({ accountNumber: acct, password: PASSWORD }),
    });
    const cookieB = cookieFrom(loginRes);

    await doRequest(env, 'DELETE', '/v1/account', {
      headers: { cookie },
      body: JSON.stringify({ password: PASSWORD }),
    });

    const create = await doRequest(env, 'POST', '/v1/topics', {
      headers: { cookie: cookieB },
      body: JSON.stringify({ name: 'zombie' }),
    });
    expect(create.status).toBe(401);
  });

  it('device tokens carry scope, label, and a 30-day expiry', async () => {
    await register();
    const before = Date.now();

    const res = await doRequest(env, 'POST', '/v1/device-tokens', {
      headers: { cookie },
      body: JSON.stringify({ label: 'Pixel 9', scope: 'manage' }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { token: string; id: string; scope: string; expiresAt: number };
    expect(body.scope).toBe('manage');
    expect(body.expiresAt - before).toBeGreaterThanOrEqual(30 * 86400 * 1000 - 2000);

    const plain = await doRequest(env, 'POST', '/v1/device-tokens', { headers: { cookie }, body: JSON.stringify({}) });
    const plainBody = (await plain.json()) as { scope: string };
    expect(plainBody.scope).toBe('push');

    const list = await doRequest(env, 'GET', '/v1/device-tokens', { headers: { cookie } });
    const listBody = (await list.json()) as { tokens: { id: string; scope: string; label: string; expiresAt: number }[] };
    expect(listBody.tokens).toHaveLength(2);
    expect(listBody.tokens.some((t) => t.scope === 'manage' && t.label === 'Pixel 9' && typeof t.expiresAt === 'number')).toBe(true);
  });

  it('lets a manage-scope device token publish and manage, and denies push-scope', async () => {
    await register();
    await doRequest(env, 'POST', '/v1/topics', { headers: { cookie }, body: JSON.stringify({ name: 'iot' }) });

    const manageRes = await doRequest(env, 'POST', '/v1/device-tokens', {
      headers: { cookie },
      body: JSON.stringify({ scope: 'manage' }),
    });
    const manageTok = ((await manageRes.json()) as { token: string }).token;

    const pub = await doRequest(env, 'POST', '/v1/publish/iot', {
      headers: { Authorization: 'Bearer ' + manageTok, 'Content-Type': 'text/plain' },
      body: 'from device',
    });
    expect(pub.status).toBe(200);

    const feed = await doRequest(env, 'GET', '/v1/messages/iot', { headers: { Authorization: 'Bearer ' + manageTok } });
    expect(feed.status).toBe(200);

    const create = await doRequest(env, 'POST', '/v1/topics', {
      headers: { Authorization: 'Bearer ' + manageTok },
      body: JSON.stringify({ name: 'hq' }),
    });
    expect(create.status).toBe(201);

    const pushRes = await doRequest(env, 'POST', '/v1/device-tokens', { headers: { cookie }, body: JSON.stringify({}) });
    const pushTok = ((await pushRes.json()) as { token: string }).token;

    const denied = await doRequest(env, 'POST', '/v1/publish/iot', {
      headers: { Authorization: 'Bearer ' + pushTok, 'Content-Type': 'text/plain' },
      body: 'nope',
    });
    expect(denied.status).toBe(401);

    const deniedFeed = await doRequest(env, 'GET', '/v1/messages/iot', { headers: { Authorization: 'Bearer ' + pushTok } });
    expect(deniedFeed.status).toBe(401);

    const deniedTopics = await doRequest(env, 'GET', '/v1/topics', { headers: { Authorization: 'Bearer ' + pushTok } });
    expect(deniedTopics.status).toBe(401);
  });

  it('works with a session sent as Authorization: Bearer', async () => {
    await register();
    const loginRes = await doRequest(env, 'POST', '/v1/login', {
      body: JSON.stringify({ accountNumber: acct, password: PASSWORD }),
    });
    expect(loginRes.status).toBe(200);
    const session = ((await loginRes.json()) as { session: string }).session;

    const info = await doRequest(env, 'GET', '/v1/account', { headers: { Authorization: 'Bearer ' + session } });
    expect(info.status).toBe(200);

    const create = await doRequest(env, 'POST', '/v1/topics', {
      headers: { Authorization: 'Bearer ' + session },
      body: JSON.stringify({ name: 'colab' }),
    });
    expect(create.status).toBe(201);

    const logout = await doRequest(env, 'POST', '/v1/logout', { headers: { Authorization: 'Bearer ' + session } });
    expect(logout.status).toBe(200);

    const after = await doRequest(env, 'GET', '/v1/account', { headers: { Authorization: 'Bearer ' + session } });
    expect(after.status).toBe(401);
  });

  it('pairs a device: code created, redeemed once, then dead', async () => {
    await register();

    const gen = await doRequest(env, 'POST', '/v1/pair-codes', { headers: { cookie } });
    expect(gen.status).toBe(200);
    const codeBody = (await gen.json()) as { code: string; expiresAt: number };
    expect(codeBody.code).toMatch(/^\d{6}$/);
    expect(codeBody.expiresAt - Date.now()).toBeGreaterThan(9 * 60 * 1000);

    const redeem = await doRequest(env, 'POST', '/v1/pair-codes/redeem', {
      body: JSON.stringify({ accountNumber: acct, code: codeBody.code }),
    });
    expect(redeem.status).toBe(200);
    const redeemed = (await redeem.json()) as { accountNumber: string; session: string };
    expect(redeemed.accountNumber).toBe(acct);

    const info = await doRequest(env, 'GET', '/v1/account', { headers: { Authorization: 'Bearer ' + redeemed.session } });
    expect(info.status).toBe(200);

    const reuse = await doRequest(env, 'POST', '/v1/pair-codes/redeem', {
      body: JSON.stringify({ accountNumber: acct, code: codeBody.code }),
    });
    expect(reuse.status).toBe(401);
  });

  it('rejects an expired or account-mismatched pair code', async () => {
    await register();

    const gen = await doRequest(env, 'POST', '/v1/pair-codes', { headers: { cookie } });
    const codeBody = (await gen.json()) as { code: string };

    const wrongAcct = await doRequest(env, 'POST', '/v1/pair-codes/redeem', {
      body: JSON.stringify({ accountNumber: '9999999999', code: codeBody.code }),
    });
    expect(wrongAcct.status).toBe(401);

    const gen2 = await doRequest(env, 'POST', '/v1/pair-codes', { headers: { cookie } });
    const code2 = ((await gen2.json()) as { code: string }).code;
    const hash = await sha256Hex(code2);
    await env.KEYS.delete((await import('../src/kvkeys')).pairCodeKey(acct, hash));
    await env.KEYS.delete((await import('../src/kvkeys')).pairCodeActiveKey(acct));

    const expired = await doRequest(env, 'POST', '/v1/pair-codes/redeem', {
      body: JSON.stringify({ accountNumber: acct, code: code2 }),
    });
    expect(expired.status).toBe(401);
  });

  it('rate limits repeated failed pair redeems', async () => {
    await register();
    const codes: { code: string }[] = [];
    for (let i = 0; i < 2; i++) {
      const gen = await doRequest(env, 'POST', '/v1/pair-codes', { headers: { cookie } });
      codes.push((await gen.json()) as { code: string });
    }

    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await doRequest(env, 'POST', '/v1/pair-codes/redeem', {
        body: JSON.stringify({ accountNumber: acct, code: codes[0]!.code }),
      });
      statuses.push(res.status);
    }
    expect(statuses).toEqual([401, 401, 401, 401, 401]);

    const blocked = await doRequest(env, 'POST', '/v1/pair-codes/redeem', {
      body: JSON.stringify({ accountNumber: acct, code: codes[1]!.code }),
    });
    expect(blocked.status).toBe(429);
  });

  it('a new pair code invalidates the previous one', async () => {
    await register();
    const first = await doRequest(env, 'POST', '/v1/pair-codes', { headers: { cookie } });
    const firstCode = ((await first.json()) as { code: string }).code;
    const second = await doRequest(env, 'POST', '/v1/pair-codes', { headers: { cookie } });
    const secondCode = ((await second.json()) as { code: string }).code;

    const oldCode = await doRequest(env, 'POST', '/v1/pair-codes/redeem', {
      body: JSON.stringify({ accountNumber: acct, code: firstCode }),
    });
    expect(oldCode.status).toBe(401);

    const newCode = await doRequest(env, 'POST', '/v1/pair-codes/redeem', {
      body: JSON.stringify({ accountNumber: acct, code: secondCode }),
    });
    expect(newCode.status).toBe(200);
  });

  it('changing the password revokes all device tokens', async () => {
    await register();
    await doRequest(env, 'POST', '/v1/topics', { headers: { cookie }, body: JSON.stringify({ name: 'lock' }) });

    const dtRes = await doRequest(env, 'POST', '/v1/device-tokens', {
      headers: { cookie },
      body: JSON.stringify({ scope: 'manage' }),
    });
    const tok = ((await dtRes.json()) as { token: string }).token;

    const change = await doRequest(env, 'POST', '/v1/account/password', {
      headers: { cookie },
      body: JSON.stringify({ oldPassword: PASSWORD, newPassword: 'a new and longer password 42' }),
    });
    expect(change.status).toBe(200);

    const pub = await doRequest(env, 'POST', '/v1/publish/lock', {
      headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'text/plain' },
      body: 'ghost',
    });
    expect(pub.status).toBe(401);
  });
});
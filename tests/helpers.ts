import { Hasher } from '../src/hasher';
import { RateLimiter } from '../src/ratelimit';
import type { Env } from '../src/env';

export function fakeKV() {
  const store = new Map<string, { v: string; exp: number }>();
  return {
    async get(key: string, type?: 'json'): Promise<string | Record<string, unknown> | null> {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.exp && entry.exp < Date.now()) {
        store.delete(key);
        return null;
      }
      return type === 'json' ? JSON.parse(entry.v) : entry.v;
    },
    async put(key: string, val: string, opts?: { expirationTtl?: number }): Promise<void> {
      store.set(key, { v: val, exp: opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : 0 });
    },
    async delete(key: string): Promise<void> {
      store.delete(key);
    },
  } as unknown as KVNamespace;
}

export function fakeDOState() {
  return { storage: fakeKV() } as unknown as DurableObjectState;
}

export function fakeDONamespace<
  T extends { fetch(request: Request): Promise<Response> },
>(factory: (name: string) => T) {
  const instances = new Map<string, T>();
  return {
    idFromName(name: string) {
      return { name };
    },
    get(id: { name: string }) {
      if (!instances.has(id.name)) instances.set(id.name, factory(id.name));
      return {
        fetch: (input: RequestInfo | URL, init?: RequestInit) => {
          const req = input instanceof Request ? input : new Request(input as string, init);
          return instances.get(id.name)!.fetch(req);
        },
      };
    },
  } as unknown as DurableObjectNamespace;
}

export function testEnv(partial: Partial<Env> = {}): Env {
  const env = {
    ACCOUNTS: fakeKV(),
    SESSIONS: fakeKV(),
    TOPICS: fakeKV(),
    KEYS: fakeKV(),
    FEEDS: fakeKV(),
    PEPPER: 'test-pepper-0123456789abcdef',
    VAPID_PUBLIC_KEY: 'BOkZMIPBOpgqGU2v5yeL2gH9nSW6fAX6UwveXX73x0a6KAcFgh6w8FlE9LnT2W1floNKQQXLBrnLSOwN-dNEXlI',
    VAPID_PRIVATE_KEY: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    VAPID_SUBJECT: 'mailto:test@example.com',
  } as unknown as Env;

  const HASHER = fakeDONamespace(() => new Hasher(fakeDOState(), env));
  const RATE_LIMITER = fakeDONamespace(() => new RateLimiter(fakeDOState(), env));

  if (partial.HASHER) env.HASHER = partial.HASHER;
  else env.HASHER = HASHER;
  if (partial.RATE_LIMITER) env.RATE_LIMITER = partial.RATE_LIMITER;
  else env.RATE_LIMITER = RATE_LIMITER;

  for (const k of ['PEPPER', 'VAPID_PUBLIC_KEY', 'VAPID_PRIVATE_KEY', 'VAPID_SUBJECT'] as const) {
    if (partial[k] !== undefined) (env as unknown as Record<string, unknown>)[k] = partial[k];
  }
  return env;
}

export function collectCtx() {
  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil(p: Promise<unknown>) {
      pending.push(p);
    },
    pending,
    async settle() {
      await Promise.allSettled(pending);
    },
  };
  return ctx;
}

export async function doRequest(env: Env, method: string, path: string, opts: { body?: BodyInit | null; headers?: Record<string, string> } = {}) {
  const { handleRequest } = await import('../src/index');
  const req = new Request('https://bs-notify.local' + path, {
    method,
    headers: { ...opts.headers },
    body: opts.body ?? null,
  });
  const ctx = collectCtx();
  const res = await handleRequest(req, env, ctx);
  await ctx.settle();
  return res;
}

export function cookieFrom(res: Response): string {
  const setCookie = res.headers.get('Set-Cookie');
  if (!setCookie) return '';
  return setCookie.split(';')[0];
}
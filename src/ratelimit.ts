import { BAN_FAILURES, BAN_WINDOW_MS } from './config';
import type { Env, KeyPerms } from './env';
import { jsonResponse } from './util';

type Op = 'check' | 'fail' | 'success';

interface RateState {
  fails: number;
  bannedUntil: number;
  acct: Record<string, number>;
}

export class RateLimiter {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  private async read(): Promise<RateState> {
    return (await this.state.storage.get<RateState>('state')) ?? { fails: 0, bannedUntil: 0, acct: {} };
  }

  private async write(s: RateState): Promise<void> {
    await this.state.storage.put('state', s);
  }

  async fetch(request: Request): Promise<Response> {
    const body = (await request.json()) as { op?: Op; acct?: string };
    const now = Date.now();
    const state = await this.read();
    if (state.bannedUntil <= now) state.bannedUntil = 0;

    if (body.op === 'check') {
      const banned = state.bannedUntil > now;
      return jsonResponse({ banned, retryAfterMs: banned ? state.bannedUntil - now : 0 });
    }

    if (body.op === 'success') {
      state.fails = 0;
      state.bannedUntil = 0;
      if (body.acct) delete state.acct[body.acct];
      await this.write(state);
      return jsonResponse({ banned: false, retryAfterMs: 0 });
    }

    if (body.op === 'fail') {
      state.fails += 1;
      if (body.acct) state.acct[body.acct] = (state.acct[body.acct] ?? 0) + 1;
      if (state.fails >= BAN_FAILURES) state.bannedUntil = now + BAN_WINDOW_MS;
      await this.write(state);
      return jsonResponse({ banned: state.bannedUntil > now, retryAfterMs: Math.max(0, state.bannedUntil - now) });
    }

    return jsonResponse({ error: 'bad request' }, 400);
  }
}

export async function rateLimitOp(env: Env, ip: string, op: Op, acct?: string): Promise<{ banned: boolean; retryAfterMs: number }> {
  const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName('ip:' + ip));
  const res = await stub.fetch('https://internal/ratelimit', {
    method: 'POST',
    body: JSON.stringify({ op, acct }),
  });
  return (await res.json()) as { banned: boolean; retryAfterMs: number };
}

export function checkPerm(rec: { perms: KeyPerms }, need: 'read' | 'write'): boolean {
  return rec.perms === need || rec.perms === 'readwrite';
}
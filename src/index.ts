import type { Env } from './env';
import {
  error,
  jsonResponse,
  applySecurityHeaders,
  clientIp,
  validateTopicName,
} from './util';
import { canManage, getApiKeyRecord, getDeviceTokenRecord, getPrincipal, unauthorized } from './auth';
import { checkPerm } from './ratelimit';
import {
  handleAccountDelete,
  handleAccountInfo,
  handleDeviceTokenCreate,
  handleDeviceTokenDelete,
  handleDeviceTokenList,
  handleLogin,
  handleLogout,
  handlePairCodeCreate,
  handlePairCodeRedeem,
  handlePasswordChange,
  handleRegister,
} from './accounts';
import {
  handleKeyCreate,
  handleKeyDelete,
  handleKeyList,
  handleSubscriberDelete,
  handleSubscriberList,
  handleTopicCreate,
  handleTopicDelete,
  handleTopicList,
  topicBelongsTo,
} from './topics';
import {
  handleMessages,
  handlePublish,
  handleSubscribe,
  handleUnsubscribe,
} from './publish';
import type { AppContext } from './publish';

const PASSTHROUGH_CTX: AppContext = { waitUntil: (p) => void p.catch(() => undefined) };

export { Hasher } from './hasher';
export { RateLimiter } from './ratelimit';

export async function handleRequest(request: Request, env: Env, ctx?: AppContext): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method;
  const segs = url.pathname.split('/').filter(Boolean);

  if (segs[0] === 'v1') {
    const res = await routeApi(request, env, ctx ?? PASSTHROUGH_CTX, method, segs.slice(1));
    return res;
  }

  return serveAsset(request, env);
}

async function withSession(env: Env, request: Request, fn: (acct: string) => Promise<Response>): Promise<Response> {
  const p = await getPrincipal(request, env);
  return canManage(p) ? fn(p!.acct) : unauthorized();
}

async function routeApi(request: Request, env: Env, ctx: AppContext, method: string, segs: string[]): Promise<Response> {
  const ip = clientIp(request);

  if (segs.length === 1) {
    if (segs[0] === 'health' && method === 'GET') return jsonResponse({ ok: true });
    if (segs[0] === 'register' && method === 'POST') return handleRegister(request, env, ip);
    if (segs[0] === 'login' && method === 'POST') return handleLogin(request, env, ip);
    if (segs[0] === 'logout' && method === 'POST') return handleLogout(request, env);
    if (segs[0] === 'account' && method === 'GET') return withSession(env, request, (a) => handleAccountInfo(request, env, a));
    if (segs[0] === 'account' && method === 'DELETE') return withSession(env, request, (a) => handleAccountDelete(request, env, a));
    if (segs[0] === 'topics' && method === 'GET') return withSession(env, request, (a) => handleTopicList(env, a));
    if (segs[0] === 'topics' && method === 'POST') return withSession(env, request, (a) => handleTopicCreate(request, env, a));
    if (segs[0] === 'device-tokens' && method === 'GET') return withSession(env, request, (a) => handleDeviceTokenList(env, a));
    if (segs[0] === 'device-tokens' && method === 'POST') return withSession(env, request, (a) => handleDeviceTokenCreate(request, env, a));
    if (segs[0] === 'pair-codes' && method === 'POST') return withSession(env, request, (a) => handlePairCodeCreate(env, a));
    return error(404, 'not found');
  }

  if (segs.length === 2) {
    if (segs[0] === 'pair-codes' && segs[1] === 'redeem' && method === 'POST') return handlePairCodeRedeem(request, env, ip);
    if (segs[0] === 'account' && segs[1] === 'password' && method === 'POST') {
      return withSession(env, request, (a) => handlePasswordChange(request, env, a));
    }
    if (segs[0] === 'messages' && method === 'GET') {
      const topic = validateTopicName(segs[1]);
      if (!topic) return error(400, 'invalid topic');
      const p = await getPrincipal(request, env);
      if (canManage(p)) return handleMessages(request, env, p!.acct, topic);
      const keyRec = await getApiKeyRecord(request, env);
      if (keyRec && keyRec.topic === topic && checkPerm(keyRec, 'read')) {
        return handleMessages(request, env, keyRec.acct, topic);
      }
      return unauthorized();
    }
    if (segs[0] === 'publish' && method === 'POST') {
      const topic = validateTopicName(segs[1]);
      if (!topic) return error(400, 'invalid topic');
      const keyRec = await getApiKeyRecord(request, env);
      if (keyRec && keyRec.topic === topic && checkPerm(keyRec, 'write')) {
        return handlePublish(request, env, keyRec.acct, topic, ctx);
      }
      const p = await getPrincipal(request, env);
      if (canManage(p) && (await topicBelongsTo(env, p!.acct, topic))) {
        return handlePublish(request, env, p!.acct, topic, ctx);
      }
      return unauthorized();
    }
    if (segs[0] === 'topics' && method === 'DELETE') {
      const topic = validateTopicName(segs[1]);
      if (!topic) return error(400, 'invalid topic');
      return withSession(env, request, (a) => handleTopicDelete(env, a, topic));
    }
    return error(404, 'not found');
  }

  if (segs.length === 3) {
    if (segs[0] === 'device-tokens' && method === 'DELETE') {
      return withSession(env, request, (a) => handleDeviceTokenDelete(request, env, a, segs[1]));
    }
  }

  if (segs.length >= 3 && segs[0] === 'topics') {
    const topic = validateTopicName(segs[1]);
    if (!topic) return error(400, 'invalid topic');

    if (segs[2] === 'subscribe') {
      if (method === 'DELETE' && segs.length === 4) {
        const dev = await getDeviceTokenRecord(request, env);
        return dev ? handleUnsubscribe(request, env, dev.acct, topic, segs[3]) : unauthorized();
      }
      if (method === 'POST' && segs.length === 3) {
        const dev = await getDeviceTokenRecord(request, env);
        return dev ? handleSubscribe(request, env, dev.acct, topic) : unauthorized();
      }
      return error(405, 'method not allowed');
    }

    if (segs[2] === 'subscribers' && method === 'GET' && segs.length === 3) {
      return withSession(env, request, (a) => handleSubscriberList(env, a, topic));
    }

    if (segs[2] === 'subscribers' && method === 'DELETE' && segs.length === 4) {
      return withSession(env, request, (a) => handleSubscriberDelete(env, a, topic, segs[3]));
    }

    if (segs[2] === 'keys') {
      if (segs.length === 3 && method === 'GET') return withSession(env, request, (a) => handleKeyList(env, a, topic));
      if (segs.length === 3 && method === 'POST') return withSession(env, request, (a) => handleKeyCreate(request, env, a, topic));
      if (segs.length === 4 && method === 'DELETE') return withSession(env, request, (a) => handleKeyDelete(request, env, a, topic, segs[3]));
      return error(405, 'method not allowed');
    }

    return error(404, 'not found');
  }

  return error(404, 'not found');
}

async function serveAsset(request: Request, env: Env): Promise<Response> {
  if (env.ASSETS) {
    const res = await env.ASSETS.fetch(request);
    const headers = new Headers(res.headers);
    headers.set('Cache-Control', 'no-store');
    applySecurityHeaders(headers);
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  }
  return error(404, 'not found');
}

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    try {
      return await handleRequest(request, env, { waitUntil: (p) => ctx.waitUntil(p) });
    } catch (err) {
      console.error('uncaught', request.method, request.url, err instanceof Error ? err.stack : String(err));
      return jsonResponse({ error: 'internal error' }, 500);
    }
  },
};
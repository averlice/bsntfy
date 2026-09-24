import { FEED_MAX, FEED_TTL_S, MAX_PUBLISH_BYTES, MAX_SUBS_PER_TOPIC } from './config';
import type { Env, FeedMsg, SubRecord } from './env';
import { checkSoftLimit, error, getIndex, jsonResponse, randomBytesN, readJson, sha256Hex, TE, bytesToB64u } from './util';
import { feedKey, subKey, subsIdxKey, topicKey } from './kvkeys';
import { deliverPush } from './webpush';
import { validateEndpoint } from './ssrf';
import { authorizeKeyForTopic, removeSubscriber, topicBelongsTo } from './topics';

export interface AppContext {
  waitUntil(p: Promise<unknown>): void;
}

interface SubscribeBody {
  endpoint?: unknown;
  keys?: unknown;
}

export async function handleSubscribe(request: Request, env: Env, acct: string, topic: string): Promise<Response> {
  if (!(await topicBelongsTo(env, acct, topic))) return error(404, 'topic not found');

  const allow = await checkSoftLimit(env, `sub:${acct}:${topic}`, 60, 300);
  if (!allow) return error(429, 'too many subscriptions, slow down');

  const body = await readJson<SubscribeBody>(request);
  const endpoint = typeof body?.endpoint === 'string' ? body.endpoint : null;
  if (!endpoint) return error(400, 'endpoint required');

  const validation = await validateEndpoint(endpoint);
  if (!validation.ok) return error(400, `invalid endpoint: ${validation.reason}`);

  const subId = (await sha256Hex(endpoint)).slice(0, 16);
  const existing = await env.TOPICS.get(subKey(acct, topic, subId));
  if (existing) return jsonResponse({ ok: true, id: subId, already: true });

  const subs = await getIndex<SubRecord>(env.TOPICS, subsIdxKey(acct, topic));
  if (subs.length >= MAX_SUBS_PER_TOPIC) return error(409, 'subscriber limit reached for this topic');

  let p256dh = '';
  let auth = '';
  const keys = body?.keys;
  if (keys && typeof keys === 'object' && !Array.isArray(keys)) {
    const k = keys as Record<string, unknown>;
    if (typeof k.p256dh === 'string' && typeof k.auth === 'string') {
      p256dh = k.p256dh;
      auth = k.auth;
    }
  }

  const sub: SubRecord = { id: subId, endpoint, p256dh, auth, created: Date.now() };
  await env.TOPICS.put(subKey(acct, topic, subId), JSON.stringify(sub));
  await env.TOPICS.put(
    subsIdxKey(acct, topic),
    JSON.stringify([...subs, sub].slice(-MAX_SUBS_PER_TOPIC)),
  );
  return jsonResponse({ ok: true, id: subId, encrypted: Boolean(p256dh && auth) }, 201);
}

export async function handleUnsubscribe(request: Request, env: Env, acct: string, topic: string, idParam: string): Promise<Response> {
  if (!(await topicBelongsTo(env, acct, topic))) return error(404, 'topic not found');
  if (!(await removeSubscriber(env, acct, topic, idParam))) return error(404, 'subscription not found');
  return jsonResponse({ ok: true });
}

async function prependFeed(env: Env, acct: string, topic: string, msg: FeedMsg): Promise<void> {
  const arr = await getIndex<FeedMsg>(env.FEEDS, feedKey(acct, topic));
  arr.unshift(msg);
  if (arr.length > FEED_MAX) arr.length = FEED_MAX;
  await env.FEEDS.put(feedKey(acct, topic), JSON.stringify(arr), { expirationTtl: FEED_TTL_S });
}

export async function handlePublish(request: Request, env: Env, acct: string, topic: string, ctx: AppContext): Promise<Response> {
  const existing = await env.TOPICS.get(topicKey(acct, topic));
  if (!existing) return error(404, 'topic not found');

  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength === 0) return error(400, 'empty message');
  if (bytes.byteLength > MAX_PUBLISH_BYTES) return error(413, 'message too large');

  const bodyText = new TextDecoder().decode(bytes);
  const msg: FeedMsg = { id: bytesToB64u(randomBytesN(9)), time: Date.now(), body: bodyText };
  await prependFeed(env, acct, topic, msg);

  const subs = await getIndex<SubRecord>(env.TOPICS, subsIdxKey(acct, topic));
  const pending: Promise<unknown>[] = [];
  for (const sub of subs) {
    pending.push(deliverOne(env, acct, topic, sub, bodyText));
  }
  for (const p of pending) {
    if (ctx?.waitUntil) ctx.waitUntil(p);
    else p.catch(() => undefined);
  }
  return jsonResponse({ ok: true, id: msg.id });
}

async function deliverOne(env: Env, acct: string, topic: string, sub: SubRecord, bodyText: string): Promise<void> {
  try {
    const res = await deliverPush(env, sub, TE.encode(bodyText));
    if (res.status === 403 || res.status === 404 || res.status === 410) {
      await env.TOPICS.delete(subKey(acct, topic, sub.id));
      await env.TOPICS.put(
        subsIdxKey(acct, topic),
        JSON.stringify((await getIndex<SubRecord>(env.TOPICS, subsIdxKey(acct, topic))).filter((s) => s.id !== sub.id)),
      );
    }
  } catch {
    await Promise.resolve();
  }
}

export async function handleMessages(request: Request, env: Env, acct: string, topic: string): Promise<Response> {
  const hasTopic = await topicBelongsTo(env, acct, topic);
  if (hasTopic) {
    const msgs = await getIndex<FeedMsg>(env.FEEDS, feedKey(acct, topic));
    return jsonResponse({ messages: msgs });
  }
  return error(404, 'topic not found');
}

export { authorizeKeyForTopic };
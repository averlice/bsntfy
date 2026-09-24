import { MAX_KEYS_PER_TOPIC, MAX_SUBS_PER_TOPIC } from './config';
import type { Env, KeyRecord, SubRecord } from './env';
import { deleteTopicCascade, isPerm } from './accounts';
import { apikeyKey, apikeysIdxKey, subKey, subsIdxKey, topicKey, topicsIdxKey } from './kvkeys';
import { checkPerm } from './ratelimit';
import {
  error,
  getIndex,
  indexAdd,
  indexRemove,
  jsonResponse,
  randToken,
  readJson,
  sha256Hex,
  validateTopicName,
} from './util';

interface TopicCreateBody {
  name?: unknown;
}

interface KeyCreateBody {
  label?: unknown;
  perms?: unknown;
}

export async function handleTopicCreate(request: Request, env: Env, acct: string): Promise<Response> {
  const body = await readJson<TopicCreateBody>(request);
  const name = validateTopicName(body?.name);
  if (!name) return error(400, 'topic name must be 2-32 chars of [a-z0-9_-] starting with a letter or digit');

  const existing = await env.TOPICS.get(topicKey(acct, name));
  if (existing) return error(409, 'topic already exists');

  await env.TOPICS.put(topicKey(acct, name), JSON.stringify({ acct, name, created: Date.now() }));
  await indexAdd<string>(env.TOPICS, topicsIdxKey(acct), name);
  return jsonResponse({ name }, 201);
}

export async function handleTopicList(env: Env, acct: string): Promise<Response> {
  const names = await getIndex<string>(env.TOPICS, topicsIdxKey(acct));
  return jsonResponse({ topics: names });
}

export async function topicBelongsTo(env: Env, acct: string, name: string): Promise<boolean> {
  return (await env.TOPICS.get(topicKey(acct, name))) !== null;
}

export async function handleKeyList(env: Env, acct: string, topic: string): Promise<Response> {
  if (!(await topicBelongsTo(env, acct, topic))) return error(404, 'topic not found');
  const ids = await getIndex<string>(env.KEYS, apikeysIdxKey(acct, topic));
  const keys: { id: string; perms: string; label: string; created: number }[] = [];
  for (const id of ids) {
    const rec = await env.KEYS.get<KeyRecord>(apikeyKey(id), 'json');
    if (rec) keys.push({ id: rec.id.slice(0, 12), perms: rec.perms, label: rec.label, created: rec.created });
  }
  return jsonResponse({ keys });
}

export async function handleKeyCreate(request: Request, env: Env, acct: string, topic: string): Promise<Response> {
  if (!(await topicBelongsTo(env, acct, topic))) return error(404, 'topic not found');

  const body = await readJson<KeyCreateBody>(request);
  if (!isPerm(body?.perms)) return error(400, 'perms must be one of: read, write, readwrite');
  const label = typeof body?.label === 'string' ? body.label.slice(0, 60) : '';

  const existing = await getIndex<string>(env.KEYS, apikeysIdxKey(acct, topic));
  if (existing.length >= MAX_KEYS_PER_TOPIC) return error(409, 'key limit reached for this topic');

  const token = randToken('fy_', 32);
  const id = await sha256Hex(token);
  const rec: KeyRecord = { id, acct, topic, perms: body.perms, label, created: Date.now() };
  await env.KEYS.put(apikeyKey(id), JSON.stringify(rec));
  await indexAdd<string>(env.KEYS, apikeysIdxKey(acct, topic), id, MAX_KEYS_PER_TOPIC);
  return jsonResponse({ topic, key: token, id: id.slice(0, 12), perms: rec.perms }, 201);
}

export async function handleKeyDelete(request: Request, env: Env, acct: string, topic: string, idParam: string): Promise<Response> {
  if (!(await topicBelongsTo(env, acct, topic))) return error(404, 'topic not found');
  const ids = await getIndex<string>(env.KEYS, apikeysIdxKey(acct, topic));
  let full: string | null = null;
  for (const id of ids) {
    if (id === idParam || id.slice(0, 12) === idParam) {
      full = id;
      break;
    }
  }
  if (!full) return error(404, 'key not found');
  await env.KEYS.delete(apikeyKey(full));
  await indexRemove<string>(env.KEYS, apikeysIdxKey(acct, topic), (id) => id === full);
  return jsonResponse({ ok: true });
}

export async function handleSubscriberList(env: Env, acct: string, topic: string): Promise<Response> {
  if (!(await topicBelongsTo(env, acct, topic))) return error(404, 'topic not found');
  const subs = await getIndex<SubRecord>(env.TOPICS, subsIdxKey(acct, topic));
  const out = subs.map((s) => ({ id: s.id, endpoint: s.endpoint, encrypted: Boolean(s.p256dh && s.auth), created: s.created }));
  return jsonResponse({ count: out.length, subscribers: out });
}

export async function removeSubscriber(env: Env, acct: string, topic: string, idParam: string): Promise<boolean> {
  const subs = await getIndex<SubRecord>(env.TOPICS, subsIdxKey(acct, topic));
  const target = subs.find((s) => s.id === idParam);
  if (!target) return false;
  await env.TOPICS.delete(subKey(acct, topic, target.id));
  await env.TOPICS.put(subsIdxKey(acct, topic), JSON.stringify(subs.filter((s) => s.id !== idParam)));
  return true;
}

export async function handleSubscriberDelete(env: Env, acct: string, topic: string, idParam: string): Promise<Response> {
  if (!(await topicBelongsTo(env, acct, topic))) return error(404, 'topic not found');
  if (!(await removeSubscriber(env, acct, topic, idParam))) return error(404, 'subscription not found');
  return jsonResponse({ ok: true });
}

export async function handleTopicDelete(env: Env, acct: string, topic: string): Promise<Response> {
  if (!(await topicBelongsTo(env, acct, topic))) return error(404, 'topic not found');
  await deleteTopicCascade(env, acct, topic);
  await indexRemove<string>(env.TOPICS, topicsIdxKey(acct), (n) => n === topic);
  return jsonResponse({ ok: true });
}

export async function authorizeKeyForTopic(env: Env, keyRec: KeyRecord | null, topic: string, need: 'read' | 'write'): Promise<boolean> {
  return Boolean(keyRec && keyRec.topic === topic && checkPerm(keyRec, need));
}

export { MAX_SUBS_PER_TOPIC, subKey, subsIdxKey };
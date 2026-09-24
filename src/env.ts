export interface Env {
  ACCOUNTS: KVNamespace;
  SESSIONS: KVNamespace;
  TOPICS: KVNamespace;
  KEYS: KVNamespace;
  FEEDS: KVNamespace;
  HASHER: DurableObjectNamespace;
  RATE_LIMITER: DurableObjectNamespace;
  ASSETS?: Fetcher;
  PEPPER: string;
  VAPID_PUBLIC_KEY: string;
  VAPID_PRIVATE_KEY: string;
  VAPID_SUBJECT: string;
}

export interface SessRecord {
  acct: string;
  created: number;
}

export interface AccountRecord {
  acct: string;
  phc: string;
  created: number;
}

export type KeyPerms = 'read' | 'write' | 'readwrite';

export interface KeyRecord {
  id: string;
  acct: string;
  topic: string;
  perms: KeyPerms;
  label: string;
  created: number;
}

export interface DeviceTokenRecord {
  id: string;
  acct: string;
  label: string;
  scope: DeviceScope;
  created: number;
  expiresAt: number;
}

export type DeviceScope = 'push' | 'manage';

export interface PairCodeRecord {
  acct: string;
  hash: string;
  created: number;
  expiresAt: number;
}

export interface SubRecord {
  id: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  created: number;
}

export interface FeedMsg {
  id: string;
  time: number;
  body: string;
}
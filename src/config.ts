export const PBKDF2 = {
  iterations: 100000,
  rounds: 3,
  keyLenBytes: 32,
  saltLenBytes: 16,
} as const;

export const BAN_FAILURES = 3;
export const BAN_WINDOW_MS = 48 * 3600 * 1000;
export const SESSION_TTL_S = 7 * 86400;
export const SESSION_COOKIE = 'fy_session';
export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 128;
export const MAX_JSON_BYTES = 16 * 1024;
export const MAX_PUBLISH_BYTES = 4096;
export const MAX_PRIVATE_MSG_BYTES = MAX_PUBLISH_BYTES - 1 - 16 - 86;
export const FEED_TTL_S = 3 * 86400;
export const FEED_MAX = 50;
export const MAX_SUBS_PER_TOPIC = 100;
export const MAX_KEYS_PER_TOPIC = 20;
export const MAX_DEVICE_TOKENS = 20;
export const DEVICE_TOKEN_TTL_S = 30 * 86400;
export const PAIR_CODE_TTL_S = 10 * 60;
export const PAIR_CODE_FAILS = 10;
export const PAIR_CODE_WINDOW_S = 3600;
export const ACC_NUM_LEN = 10;
export const REGISTER_PER_IP_H = 5;
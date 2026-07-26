/*
 * Copyright 2026 The 25-ji-code-de Team
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * 类型声明的使用测试 —— 不在运行时执行，只由 `npm run type-check` 编译。
 * 目的是防止 types/index.d.ts 与 src/index.js 悄悄漂移。
 */

import {
  createSekaiAuth,
  SekaiAuth,
  SekaiAuthError,
  normalizeProfile,
  computeCodeChallenge,
  randomHex,
  base64UrlEncode,
  SEKAI_PASS_ENDPOINTS,
  SEKAI_PASS_ISSUER,
  REFRESH_SKEW_MS,
  type SekaiProfile,
  type SekaiEndpoints,
} from './index.js';

// hub / 25ji 的用法：显式端点 + 覆盖历史 storage key
const hubAuth = createSekaiAuth({
  clientId: 'hub_client',
  redirectUri: 'https://hub.example/callback',
  endpoints: SEKAI_PASS_ENDPOINTS,
  storagePrefix: 'sekai_',
  keys: { expiresAt: 'sekai_token_expires_at', state: 'sekai_auth_state' },
});

// nightcord 的用法：前缀默认值刚好对得上，带过期回调
const nightcordAuth = new SekaiAuth({
  clientId: 'nightcord_client',
  storagePrefix: 'sekai_pass_',
  endpoints: SEKAI_PASS_ENDPOINTS,
  onAuthExpired: () => {},
});

// stickers-maker 的用法：OIDC discovery
const makerAuth = createSekaiAuth({
  clientId: 'maker_client',
  issuer: SEKAI_PASS_ISSUER,
  scope: 'openid profile email',
});

async function exercise(): Promise<void> {
  await hubAuth.login();

  const tokens = await hubAuth.handleCallback();
  const accessToken: string = tokens.access_token;
  void accessToken;

  await hubAuth.handleCallback('code', 'state');

  // getAccessToken / getUserInfo 失败返回 null 而不抛 —— 类型必须体现
  const token: string | null = await hubAuth.getAccessToken();
  void token;

  const refreshed: string | null = await nightcordAuth.refresh();
  void refreshed;

  const info: Record<string, unknown> | null = await makerAuth.getUserInfo({ cache: true });
  const profile: SekaiProfile | null = makerAuth.normalizeProfile(info);
  void profile;

  const cached: Record<string, unknown> | null = nightcordAuth.getCachedUser();
  void cached;

  const authed: boolean = hubAuth.isAuthenticated();
  void authed;

  await hubAuth.logout({ redirectTo: '/', revoke: true });
  await nightcordAuth.logout();

  const endpoints: SekaiEndpoints = await makerAuth.getEndpoints();
  void endpoints.token;

  // 解析后的 key 全部可读
  const keyName: string = hubAuth.keys.accessToken;
  void keyName;
}

async function helpers(): Promise<void> {
  const hex: string = randomHex(64);
  const challenge: string = await computeCodeChallenge(hex);
  const encoded: string = base64UrlEncode(new Uint8Array([1, 2, 3]));
  void challenge;
  void encoded;

  const p: SekaiProfile | null = normalizeProfile({ sub: 'u1', name: 'Nako' });
  void p?.avatarUrl;
  void normalizeProfile(null);

  const skew: number = REFRESH_SKEW_MS;
  void skew;
}

function errors(err: unknown): void {
  if (err instanceof SekaiAuthError) {
    const code: string = err.code;
    const status: number | undefined = err.status;
    void code;
    void status;
  }
  throw new SekaiAuthError('boom', { code: 'invalid_state', status: 400 });
}

void exercise;
void helpers;
void errors;

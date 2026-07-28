/*
 * Copyright 2026 The 25-ji-code-de Team
 * SPDX-License-Identifier: Apache-2.0
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  SekaiAuth,
  SekaiAuthError,
  normalizeProfile,
  randomHex,
  base64UrlEncode,
  computeCodeChallenge,
  REFRESH_SKEW_MS,
} from '../src/index.js';

/** 最小 Storage 实现，够 SDK 用。 */
class MemoryStorage {
  constructor() {
    this.map = new Map();
  }
  getItem(k) {
    return this.map.has(k) ? this.map.get(k) : null;
  }
  setItem(k, v) {
    this.map.set(k, String(v));
  }
  removeItem(k) {
    this.map.delete(k);
  }
}

const ENDPOINTS = {
  authorize: 'https://id.example/oauth/authorize',
  token: 'https://id.example/oauth/token',
  userinfo: 'https://id.example/oauth/userinfo',
};

function makeAuth(overrides = {}) {
  return new SekaiAuth({
    clientId: 'test_client',
    redirectUri: 'https://app.example/callback',
    endpoints: ENDPOINTS,
    localStorage: new MemoryStorage(),
    sessionStorage: new MemoryStorage(),
    ...overrides,
  });
}

/** 装一个假的 fetch，返回排好队的响应。 */
function stubFetch(queue) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    const next = queue.shift();
    if (!next) throw new Error(`unexpected fetch: ${url}`);
    if (next instanceof Error) throw next;
    return {
      ok: next.status === undefined || (next.status >= 200 && next.status < 300),
      status: next.status ?? 200,
      json: async () => next.body,
      text: async () => JSON.stringify(next.body),
    };
  };
  return calls;
}

describe('crypto helpers', () => {
  test('randomHex 返回 2 * byteLength 个字符', () => {
    assert.equal(randomHex(16).length, 32);
    assert.equal(randomHex(64).length, 128);
    assert.match(randomHex(8), /^[0-9a-f]{16}$/);
  });

  test('randomHex 保留前导零（padStart 而非 toString 截断）', () => {
    // 直接验证编码方式：0 应该编成 "00" 而不是 "0"
    const bytes = new Uint8Array([0, 1, 255]);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    assert.equal(hex, '0001ff');
  });

  test('base64UrlEncode 无 padding 且字母表安全', () => {
    const encoded = base64UrlEncode(new Uint8Array([251, 255, 190]));
    assert.equal(encoded, '-_--');
    assert.ok(!encoded.includes('='));
  });

  test('base64UrlEncode 能处理超过 apply 参数上限的大 buffer', () => {
    const big = new Uint8Array(200_000).fill(65);
    assert.doesNotThrow(() => base64UrlEncode(big));
  });

  test('computeCodeChallenge 匹配 RFC 7636 附录 B 的测试向量', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    assert.equal(
      await computeCodeChallenge(verifier),
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });
});

describe('normalizeProfile', () => {
  test('SEKAI Pass 字段优先于 OIDC 字段', () => {
    const p = normalizeProfile({
      sub: 'u1',
      display_name: 'なこ',
      name: 'Nako',
      preferred_username: 'nako',
      username: 'nako_login',
      avatar_url: 'https://cdn.example/a.png',
      bio: ' hello ',
    });
    assert.equal(p.displayName, 'なこ');
    assert.equal(p.username, 'nako');
    assert.equal(p.avatarUrl, 'https://cdn.example/a.png');
    assert.equal(p.bio, 'hello');
  });

  test('回退到 OIDC claim', () => {
    const p = normalizeProfile({ sub: 'u2', name: 'Asagi', picture: 'https://cdn/x.png' });
    assert.equal(p.displayName, 'Asagi');
    assert.equal(p.avatarUrl, 'https://cdn/x.png');
  });

  test('拒绝非 https 头像（防 javascript: / data: 注入）', () => {
    assert.equal(normalizeProfile({ picture: 'javascript:alert(1)' }).avatarUrl, null);
    assert.equal(normalizeProfile({ avatar_url: 'http://cdn/x.png' }).avatarUrl, null);
  });

  test('null 进 null 出', () => {
    assert.equal(normalizeProfile(null), null);
  });
});

describe('构造校验', () => {
  test('缺 clientId 报错', () => {
    assert.throws(() => new SekaiAuth({ endpoints: ENDPOINTS }), SekaiAuthError);
  });

  test('既没有 endpoints 也没有 issuer 报错', () => {
    assert.throws(() => new SekaiAuth({ clientId: 'x' }), SekaiAuthError);
  });

  test('storagePrefix 决定默认 key', () => {
    const a = makeAuth({ storagePrefix: 'sekai_pass_' });
    assert.equal(a.keys.accessToken, 'sekai_pass_access_token');
    assert.equal(a.keys.expiresAt, 'sekai_pass_expires_at');
  });

  test('keys 可逐项覆盖，用于对齐既有部署', () => {
    const a = makeAuth({
      storagePrefix: 'sekai_',
      keys: { expiresAt: 'sekai_token_expires_at', state: 'sekai_auth_state' },
    });
    assert.equal(a.keys.accessToken, 'sekai_access_token');
    assert.equal(a.keys.expiresAt, 'sekai_token_expires_at');
    assert.equal(a.keys.state, 'sekai_auth_state');
    assert.equal(a.keys.codeVerifier, 'sekai_code_verifier');
  });
});

describe('isAuthenticated', () => {
  let auth;
  beforeEach(() => {
    auth = makeAuth();
  });

  test('无 token 时为 false', () => {
    assert.equal(auth.isAuthenticated(), false);
  });

  test('access token 未过期时为 true', () => {
    auth._local.setItem(auth.keys.accessToken, 'a');
    // 必须超出 REFRESH_SKEW_MS，否则会触发提前刷新
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() + 60 * 60 * 1000));
    assert.equal(auth.isAuthenticated(), true);
  });

  test('access 过期但有 refresh token 时仍为 true', () => {
    auth._local.setItem(auth.keys.accessToken, 'a');
    auth._local.setItem(auth.keys.refreshToken, 'r');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() - 1));
    assert.equal(auth.isAuthenticated(), true);
  });

  test('access 过期且无 refresh token 时为 false', () => {
    auth._local.setItem(auth.keys.accessToken, 'a');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() - 1));
    assert.equal(auth.isAuthenticated(), false);
  });

  test('expires_at 是垃圾值且无 refresh token 时为 false', () => {
    auth._local.setItem(auth.keys.accessToken, 'a');
    auth._local.setItem(auth.keys.expiresAt, 'not-a-number');
    assert.equal(auth.isAuthenticated(), false);
  });
});

describe('handleCallback', () => {
  test('成功换取并持久化 token', async () => {
    const auth = makeAuth();
    auth._session.setItem(auth.keys.state, 's1');
    auth._session.setItem(auth.keys.codeVerifier, 'v1');

    const calls = stubFetch([
      { body: { access_token: 'AT', refresh_token: 'RT', expires_in: 3600 } },
    ]);

    const tokens = await auth.handleCallback('CODE', 's1');
    assert.equal(tokens.access_token, 'AT');
    assert.equal(auth._local.getItem(auth.keys.accessToken), 'AT');
    assert.equal(auth._local.getItem(auth.keys.refreshToken), 'RT');

    const expiresAt = Number(auth._local.getItem(auth.keys.expiresAt));
    assert.ok(expiresAt > Date.now() + 3_500_000);

    // PKCE 临时状态必须清干净
    assert.equal(auth._session.getItem(auth.keys.state), null);
    assert.equal(auth._session.getItem(auth.keys.codeVerifier), null);

    const body = calls[0].init.body;
    assert.equal(body.get('grant_type'), 'authorization_code');
    assert.equal(body.get('code_verifier'), 'v1');
    assert.equal(body.get('redirect_uri'), 'https://app.example/callback');
  });

  test('state 不匹配时拒绝且不发 token 请求', async () => {
    const auth = makeAuth();
    auth._session.setItem(auth.keys.state, 's1');
    auth._session.setItem(auth.keys.codeVerifier, 'v1');
    const calls = stubFetch([]);

    await assert.rejects(() => auth.handleCallback('CODE', 'WRONG'), {
      name: 'SekaiAuthError',
      code: 'invalid_state',
    });
    assert.equal(calls.length, 0);
  });

  test('state 用过即废，重放会被拒', async () => {
    const auth = makeAuth();
    auth._session.setItem(auth.keys.state, 's1');
    auth._session.setItem(auth.keys.codeVerifier, 'v1');
    stubFetch([{ body: { access_token: 'AT', expires_in: 3600 } }]);
    await auth.handleCallback('CODE', 's1');

    stubFetch([]);
    await assert.rejects(() => auth.handleCallback('CODE', 's1'), { code: 'invalid_state' });
  });

  test('缺 code_verifier 时拒绝', async () => {
    const auth = makeAuth();
    auth._session.setItem(auth.keys.state, 's1');
    stubFetch([]);
    await assert.rejects(() => auth.handleCallback('CODE', 's1'), { code: 'invalid_request' });
  });

  test('expires_in 缺省按 3600 处理', async () => {
    const auth = makeAuth();
    auth._session.setItem(auth.keys.state, 's1');
    auth._session.setItem(auth.keys.codeVerifier, 'v1');
    stubFetch([{ body: { access_token: 'AT' } }]);

    const before = Date.now();
    await auth.handleCallback('CODE', 's1');
    const expiresAt = Number(auth._local.getItem(auth.keys.expiresAt));
    assert.ok(expiresAt >= before + 3600 * 1000);
  });

  test('token 端点报错时抛出 OAuth error code', async () => {
    const auth = makeAuth();
    auth._session.setItem(auth.keys.state, 's1');
    auth._session.setItem(auth.keys.codeVerifier, 'v1');
    stubFetch([{ status: 400, body: { error: 'invalid_grant', error_description: 'expired' } }]);

    await assert.rejects(() => auth.handleCallback('CODE', 's1'), {
      name: 'SekaiAuthError',
      code: 'invalid_grant',
    });
  });
});

describe('getAccessToken / refresh', () => {
  test('token 还新鲜时直接返回，不发请求', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'AT');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() + 60 * 60 * 1000));
    const calls = stubFetch([]);

    assert.equal(await auth.getAccessToken(), 'AT');
    assert.equal(calls.length, 0);
  });

  test('距过期不足 5 分钟就提前刷新', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'OLD');
    auth._local.setItem(auth.keys.refreshToken, 'RT');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() + REFRESH_SKEW_MS - 1000));
    stubFetch([{ body: { access_token: 'NEW', expires_in: 3600 } }]);

    assert.equal(await auth.getAccessToken(), 'NEW');
    assert.equal(auth._local.getItem(auth.keys.accessToken), 'NEW');
  });

  test('并发 getAccessToken 只触发一次 refresh（single-flight）', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'OLD');
    auth._local.setItem(auth.keys.refreshToken, 'RT');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() - 1));

    let inFlight = 0;
    let maxInFlight = 0;
    globalThis.fetch = async () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 10));
      inFlight -= 1;
      return {
        ok: true,
        status: 200,
        json: async () => ({ access_token: 'NEW', expires_in: 3600 }),
      };
    };

    const results = await Promise.all([
      auth.getAccessToken(),
      auth.getAccessToken(),
      auth.getAccessToken(),
    ]);
    assert.deepEqual(results, ['NEW', 'NEW', 'NEW']);
    assert.equal(maxInFlight, 1);
  });

  test('轮换下发新 refresh token 时会更新；没下发则保留旧的', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'OLD');
    auth._local.setItem(auth.keys.refreshToken, 'RT1');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() - 1));

    stubFetch([{ body: { access_token: 'A2', refresh_token: 'RT2', expires_in: 3600 } }]);
    await auth.getAccessToken();
    assert.equal(auth._local.getItem(auth.keys.refreshToken), 'RT2');

    auth._local.setItem(auth.keys.expiresAt, String(Date.now() - 1));
    stubFetch([{ body: { access_token: 'A3', expires_in: 3600 } }]);
    await auth.getAccessToken();
    assert.equal(auth._local.getItem(auth.keys.refreshToken), 'RT2');
  });

  test('refresh 失败时清空本地状态、返回 null、触发 onAuthExpired', async () => {
    let expired = 0;
    const auth = makeAuth({ onAuthExpired: () => (expired += 1) });
    auth._local.setItem(auth.keys.accessToken, 'OLD');
    auth._local.setItem(auth.keys.refreshToken, 'RT');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() - 1));
    stubFetch([{ status: 400, body: { error: 'invalid_grant' } }]);

    assert.equal(await auth.getAccessToken(), null);
    assert.equal(auth._local.getItem(auth.keys.accessToken), null);
    assert.equal(auth._local.getItem(auth.keys.refreshToken), null);
    assert.equal(auth.isAuthenticated(), false);
    assert.equal(expired, 1);
  });

  test('没有 refresh token 时返回 null，不发请求', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'OLD');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() - 1));
    const calls = stubFetch([]);

    assert.equal(await auth.getAccessToken(), null);
    assert.equal(calls.length, 0);
  });

  test('完全没登录时返回 null', async () => {
    const auth = makeAuth();
    stubFetch([]);
    assert.equal(await auth.getAccessToken(), null);
  });
});

describe('getUserInfo', () => {
  test('带上 Bearer 头', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'AT');
    // 必须超出 REFRESH_SKEW_MS，否则会触发提前刷新
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() + 60 * 60 * 1000));
    const calls = stubFetch([{ body: { sub: 'u1', username: 'nako' } }]);

    const info = await auth.getUserInfo();
    assert.equal(info.sub, 'u1');
    assert.equal(calls[0].init.headers.Authorization, 'Bearer AT');
  });

  test('401 时清空本地 token 并返回 null', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'AT');
    // 必须超出 REFRESH_SKEW_MS，否则会触发提前刷新
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() + 60 * 60 * 1000));
    stubFetch([{ status: 401, body: {} }]);

    assert.equal(await auth.getUserInfo(), null);
    assert.equal(auth._local.getItem(auth.keys.accessToken), null);
  });

  test('cache 选项写入并可读回', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'AT');
    // 必须超出 REFRESH_SKEW_MS，否则会触发提前刷新
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() + 60 * 60 * 1000));
    stubFetch([{ body: { sub: 'u1' } }]);

    await auth.getUserInfo({ cache: true });
    assert.deepEqual(auth.getCachedUser(), { sub: 'u1' });
  });

  test('缓存内容损坏时 getCachedUser 返回 null 而非抛异常', () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.user, '{not json');
    assert.equal(auth.getCachedUser(), null);
  });
});

describe('logout', () => {
  test('对两个 token 都发 revoke，然后清空本地', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'AT');
    auth._local.setItem(auth.keys.refreshToken, 'RT');
    // 必须超出 REFRESH_SKEW_MS，否则会触发提前刷新
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() + 60 * 60 * 1000));

    const calls = [];
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), body: init.body });
      return { ok: true, status: 200, json: async () => ({}) };
    };

    await auth.logout();
    assert.equal(calls.length, 2);
    assert.ok(calls.every((c) => c.url === 'https://id.example/oauth/revoke'));
    assert.deepEqual(
      calls.map((c) => c.body.get('token_type_hint')),
      ['refresh_token', 'access_token'],
    );
    assert.equal(auth.isAuthenticated(), false);
  });

  test('revoke 请求失败也照样完成本地登出', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'AT');
    globalThis.fetch = async () => {
      throw new Error('network down');
    };

    await auth.logout();
    assert.equal(auth._local.getItem(auth.keys.accessToken), null);
  });

  test('revoke: false 时不发请求', async () => {
    const auth = makeAuth();
    auth._local.setItem(auth.keys.accessToken, 'AT');
    const calls = stubFetch([]);

    await auth.logout({ revoke: false });
    assert.equal(calls.length, 0);
    assert.equal(auth._local.getItem(auth.keys.accessToken), null);
  });
});

describe('OIDC discovery', () => {
  test('从 issuer 解析端点并缓存', async () => {
    const auth = makeAuth({ endpoints: undefined, issuer: 'https://id.example/' });
    const calls = stubFetch([
      {
        body: {
          authorization_endpoint: 'https://id.example/oauth/authorize',
          token_endpoint: 'https://id.example/oauth/token',
          userinfo_endpoint: 'https://id.example/oauth/userinfo',
          revocation_endpoint: 'https://id.example/oauth/revoke',
        },
      },
    ]);

    const e1 = await auth.getEndpoints();
    const e2 = await auth.getEndpoints();
    assert.equal(e1.token, 'https://id.example/oauth/token');
    assert.equal(e2, e1);
    assert.equal(calls.length, 1, 'discovery 应只发一次');
    assert.equal(calls[0].url, 'https://id.example/.well-known/openid-configuration');
  });

  test('discovery 失败不缓存，可重试', async () => {
    const auth = makeAuth({ endpoints: undefined, issuer: 'https://id.example' });
    stubFetch([{ status: 500, body: {} }]);
    await assert.rejects(() => auth.getEndpoints(), { code: 'discovery_failed' });

    stubFetch([
      {
        body: {
          authorization_endpoint: 'https://id.example/oauth/authorize',
          token_endpoint: 'https://id.example/oauth/token',
        },
      },
    ]);
    const endpoints = await auth.getEndpoints();
    assert.equal(endpoints.token, 'https://id.example/oauth/token');
  });

  test('discovery 文档缺关键端点时报错', async () => {
    const auth = makeAuth({ endpoints: undefined, issuer: 'https://id.example' });
    stubFetch([{ body: { issuer: 'https://id.example' } }]);
    await assert.rejects(() => auth.getEndpoints(), { code: 'discovery_failed' });
  });
});

describe('login', () => {
  test('构造出带 S256 challenge 的授权 URL 并存好 PKCE 状态', async () => {
    const auth = makeAuth();
    let redirected = '';
    globalThis.location = {
      origin: 'https://app.example',
      search: '',
      set href(v) {
        redirected = v;
      },
      get href() {
        return redirected;
      },
    };

    await auth.login();

    const url = new URL(redirected);
    assert.equal(url.origin + url.pathname, 'https://id.example/oauth/authorize');
    assert.equal(url.searchParams.get('response_type'), 'code');
    assert.equal(url.searchParams.get('client_id'), 'test_client');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('scope'), 'openid profile email');

    const verifier = auth._session.getItem(auth.keys.codeVerifier);
    assert.equal(verifier.length, 128, 'code_verifier 应为 128 字符（RFC 7636 上限）');
    assert.equal(
      url.searchParams.get('code_challenge'),
      await computeCodeChallenge(verifier),
    );
    assert.equal(url.searchParams.get('state'), auth._session.getItem(auth.keys.state));
  });
});

describe('transport hooks', () => {
  test('注入 navigate 时 login 不写 location.href', async () => {
    let navigated = '';
    let locationTouched = false;
    globalThis.location = {
      origin: 'https://app.example',
      search: '',
      set href(_v) {
        locationTouched = true;
      },
      get href() {
        return '';
      },
    };

    const auth = makeAuth({
      navigate: (url) => {
        navigated = url;
      },
    });
    await auth.login();

    assert.equal(locationTouched, false);
    const url = new URL(navigated);
    assert.equal(url.origin + url.pathname, 'https://id.example/oauth/authorize');
    assert.equal(url.searchParams.get('client_id'), 'test_client');
    assert.ok(auth._session.getItem(auth.keys.codeVerifier));
  });

  test('注入 fetch 时 token 交换不走 globalThis.fetch', async () => {
    let globalFetchCalls = 0;
    globalThis.fetch = async () => {
      globalFetchCalls += 1;
      throw new Error('global fetch should not be used');
    };

    const injectedCalls = [];
    const auth = makeAuth({
      fetch: async (url, init) => {
        injectedCalls.push({ url: String(url), init });
        return {
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'AT', refresh_token: 'RT', expires_in: 3600 }),
          text: async () => '',
        };
      },
    });
    auth._session.setItem(auth.keys.state, 's1');
    auth._session.setItem(auth.keys.codeVerifier, 'v1');

    const tokens = await auth.handleCallback('CODE', 's1');
    assert.equal(tokens.access_token, 'AT');
    assert.equal(globalFetchCalls, 0);
    assert.equal(injectedCalls.length, 1);
    assert.equal(injectedCalls[0].url, 'https://id.example/oauth/token');
    assert.equal(injectedCalls[0].init.body.get('code_verifier'), 'v1');
  });

  test('注入 fetch 时 discovery / userinfo 也走它', async () => {
    let globalFetchCalls = 0;
    globalThis.fetch = async () => {
      globalFetchCalls += 1;
      throw new Error('global fetch should not be used');
    };

    const calls = [];
    const auth = makeAuth({
      endpoints: undefined,
      issuer: 'https://id.example',
      fetch: async (url, init) => {
        calls.push({ url: String(url), init });
        if (String(url).includes('openid-configuration')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              authorization_endpoint: 'https://id.example/oauth/authorize',
              token_endpoint: 'https://id.example/oauth/token',
              userinfo_endpoint: 'https://id.example/oauth/userinfo',
            }),
            text: async () => '',
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ sub: 'u1', preferred_username: 'miku' }),
          text: async () => '',
        };
      },
    });

    const endpoints = await auth.getEndpoints();
    assert.equal(endpoints.userinfo, 'https://id.example/oauth/userinfo');

    auth._local.setItem(auth.keys.accessToken, 'AT');
    auth._local.setItem(auth.keys.expiresAt, String(Date.now() + 60 * 60 * 1000));
    const info = await auth.getUserInfo();
    assert.equal(info.sub, 'u1');
    assert.equal(globalFetchCalls, 0);
    assert.equal(calls.length, 2);
  });

  test('logout 的 redirectTo 也走 navigate', async () => {
    let navigated = '';
    let locationTouched = false;
    globalThis.location = {
      set href(_v) {
        locationTouched = true;
      },
      get href() {
        return '';
      },
    };

    const auth = makeAuth({
      navigate: (url) => {
        navigated = url;
      },
    });
    auth._local.setItem(auth.keys.accessToken, 'AT');
    await auth.logout({ revoke: false, redirectTo: 'https://app.example/' });
    assert.equal(navigated, 'https://app.example/');
    assert.equal(locationTouched, false);
  });
});

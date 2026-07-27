/*
 * Copyright 2026 The 25-ji-code-de Team
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * OIDC nonce 与 ID Token 验证的测试。
 *
 * 背景：生态里五个客户端**没有一个**做了 nonce 的闭环 ——
 * hub / 25ji / nightcord / stickers-maker 压根不发；
 * puzzle-sekai 发了但回调里从不校验（只取 access_token）。
 * 而 sekai-pass 服务端一直完整支持（存 oidc_auth_data，写进 ID Token）。
 *
 * 这里用**真实 ES256 密钥对**签 ID Token 并搭一个假 JWKS 端点，
 * 因为不验签的 nonce 校验是没有意义的 —— 能注入 token 的攻击者
 * 同样能伪造 nonce，两步必须一起做。
 */

import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { SekaiAuth, decodeJwtPayload } from '../src/index.js';

const ISSUER = 'https://id.example';
const CLIENT_ID = 'test_client';
const KID = 'sig-1';

let privateKey;
let publicJwk;
let otherPrivateKey;

before(async () => {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  privateKey = pair.privateKey;
  publicJwk = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid: KID, alg: 'ES256' };

  const other = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  otherPrivateKey = other.privateKey;
});

class MemoryStorage {
  constructor() { this.map = new Map(); }
  getItem(k) { return this.map.has(k) ? this.map.get(k) : null; }
  setItem(k, v) { this.map.set(k, String(v)); }
  removeItem(k) { this.map.delete(k); }
  clear() { this.map.clear(); }
}

function b64url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (const b of u8) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function signIdToken(claims, { key = privateKey, header = { alg: 'ES256', typ: 'JWT', kid: KID } } = {}) {
  const enc = new TextEncoder();
  const h = b64url(enc.encode(JSON.stringify(header)));
  const p = b64url(enc.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    key,
    enc.encode(`${h}.${p}`),
  );
  return `${h}.${p}.${b64url(sig)}`;
}

function baseClaims(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, sub: 'u1', aud: CLIENT_ID, exp: now + 3600, iat: now, ...overrides };
}

const local = new MemoryStorage();
const session = new MemoryStorage();
let redirectedTo = '';

function makeAuth(scope = 'openid profile') {
  return new SekaiAuth({
    clientId: CLIENT_ID,
    redirectUri: 'https://app.example/callback',
    scope,
    endpoints: {
      authorize: `${ISSUER}/oauth/authorize`,
      token: `${ISSUER}/oauth/token`,
      userinfo: `${ISSUER}/oauth/userinfo`,
    },
    localStorage: local,
    sessionStorage: session,
  });
}

/** 假 fetch：JWKS 走内置回应，其余按队列。 */
function stubFetch(queue = [], { jwks = [publicJwk] } = {}) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    calls.push({ url: u, init });
    if (u.includes('jwks')) {
      return { ok: true, status: 200, json: async () => ({ keys: jwks }) };
    }
    const next = queue.shift();
    if (!next) throw new Error(`unexpected fetch: ${u}`);
    return {
      ok: next.status === undefined || (next.status >= 200 && next.status < 300),
      status: next.status ?? 200,
      json: async () => next.body,
      text: async () => JSON.stringify(next.body),
    };
  };
  return calls;
}

beforeEach(() => {
  local.clear();
  session.clear();
  redirectedTo = '';
  globalThis.location = {
    origin: 'https://app.example',
    search: '',
    get href() { return redirectedTo; },
    set href(v) { redirectedTo = v; },
  };
});

describe('decodeJwtPayload', () => {
  test('解出 payload', async () => {
    const token = await signIdToken(baseClaims({ nonce: 'n1' }));
    assert.equal(decodeJwtPayload(token).nonce, 'n1');
  });

  test('畸形输入返回 null 而不抛', () => {
    for (const bad of ['', 'a', 'a.b', 'a.b.c.d', 'x.!!!.z']) {
      assert.equal(decodeJwtPayload(bad), null, JSON.stringify(bad));
    }
  });
});

describe('login 时发送 nonce', () => {
  test('scope 含 openid 时带上 nonce 并存进 sessionStorage', async () => {
    const auth = makeAuth('openid profile');
    await auth.login();

    const url = new URL(redirectedTo);
    const nonce = url.searchParams.get('nonce');
    assert.ok(nonce, '授权请求必须带 nonce');
    assert.equal(nonce, session.getItem(auth.keys.nonce), '必须存下来供回调比对');
    assert.match(nonce, /^[0-9a-f]{32}$/);
  });

  test('非 OIDC 请求不发 nonce', async () => {
    const auth = makeAuth('profile email');
    await auth.login();
    assert.equal(new URL(redirectedTo).searchParams.get('nonce'), null);
  });

  test('每次登录的 nonce 都不同', async () => {
    const auth = makeAuth();
    const seen = new Set();
    for (let i = 0; i < 20; i++) {
      await auth.login();
      seen.add(new URL(redirectedTo).searchParams.get('nonce'));
    }
    assert.equal(seen.size, 20);
  });

  test('nonce 与 code_verifier 一样存在 sessionStorage 而非 localStorage', async () => {
    const auth = makeAuth();
    await auth.login();
    assert.ok(session.getItem(auth.keys.nonce));
    assert.equal(local.getItem(auth.keys.nonce), null);
  });
});

describe('validateIdToken —— 签名', () => {
  test('合法签名通过，并返回 claim', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims());
    const claims = await auth.validateIdToken(token);
    assert.equal(claims.sub, 'u1');
  });

  test('别的私钥签的被拒', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims(), { key: otherPrivateKey });
    await assert.rejects(() => auth.validateIdToken(token), /signature is invalid/);
  });

  test('篡改 payload 后被拒', async () => {
    const auth = makeAuth();
    stubFetch();
    const good = await signIdToken(baseClaims());
    const [h, , s] = good.split('.');
    const evil = b64url(new TextEncoder().encode(JSON.stringify(baseClaims({ sub: 'admin' }))));
    await assert.rejects(() => auth.validateIdToken(`${h}.${evil}.${s}`), /signature is invalid/);
  });

  test('alg: none 被拒 —— 不能因为没签名就放行', async () => {
    const auth = makeAuth();
    stubFetch();
    const enc = new TextEncoder();
    const h = b64url(enc.encode(JSON.stringify({ alg: 'none', typ: 'JWT', kid: KID })));
    const p = b64url(enc.encode(JSON.stringify(baseClaims())));
    await assert.rejects(() => auth.validateIdToken(`${h}.${p}.`), /Unsupported ID token algorithm/);
  });

  test('HS256 被拒 —— 挡住「把公钥当 HMAC 密钥」', async () => {
    const auth = makeAuth();
    stubFetch();
    const enc = new TextEncoder();
    const h = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: KID })));
    const p = b64url(enc.encode(JSON.stringify(baseClaims())));
    await assert.rejects(() => auth.validateIdToken(`${h}.${p}.AAAA`), /Unsupported/);
  });

  test('JWKS 里没有匹配 kid 的密钥时被拒', async () => {
    const auth = makeAuth();
    stubFetch([], { jwks: [{ ...publicJwk, kid: 'other-kid' }] });
    const token = await signIdToken(baseClaims());
    await assert.rejects(() => auth.validateIdToken(token), /No JWKS key matches/);
  });

  test('JWKS 只拉一次并缓存', async () => {
    const auth = makeAuth();
    const calls = stubFetch();
    const token = await signIdToken(baseClaims());
    await auth.validateIdToken(token);
    await auth.validateIdToken(token);
    assert.equal(calls.filter((c) => c.url.includes('jwks')).length, 1);
  });

  test('段数不对直接拒', async () => {
    const auth = makeAuth();
    stubFetch();
    for (const bad of ['', 'a.b', 'a.b.c.d']) {
      await assert.rejects(() => auth.validateIdToken(bad), /malformed/);
    }
  });
});

describe('validateIdToken —— claim', () => {
  test('iss 不匹配被拒', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims({ iss: 'https://evil.example' }));
    await assert.rejects(() => auth.validateIdToken(token), /issuer mismatch/);
  });

  test('aud 不含本 client 被拒', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims({ aud: 'someone_else' }));
    await assert.rejects(() => auth.validateIdToken(token), /audience/);
  });

  test('aud 是数组且包含本 client 时通过', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims({ aud: ['other', CLIENT_ID] }));
    assert.ok(await auth.validateIdToken(token));
  });

  test('过期被拒（容忍 60 秒偏移）', async () => {
    const auth = makeAuth();
    stubFetch();
    const now = Math.floor(Date.now() / 1000);
    // 刚过期 30 秒的仍在 60 秒时钟容差内
    assert.ok(await auth.validateIdToken(await signIdToken(baseClaims({ exp: now - 30 }))));
    const longExpired = await signIdToken(baseClaims({ exp: now - 600 }));
    await assert.rejects(() => auth.validateIdToken(longExpired), /expired/);
  });

  test('iat 在未来太多被拒', async () => {
    const auth = makeAuth();
    stubFetch();
    const now = Math.floor(Date.now() / 1000);
    const fromTheFuture = await signIdToken(baseClaims({ iat: now + 600 }));
    await assert.rejects(() => auth.validateIdToken(fromTheFuture), /issued in the future/);
  });
});

describe('validateIdToken —— nonce', () => {
  test('nonce 匹配时通过', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims({ nonce: 'n-abc' }));
    assert.ok(await auth.validateIdToken(token, { nonce: 'n-abc' }));
  });

  test('nonce 不匹配时拒绝 —— 这就是防 token 注入的那一步', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims({ nonce: 'from-another-request' }));
    await assert.rejects(
      () => auth.validateIdToken(token, { nonce: 'mine' }),
      /nonce mismatch/,
    );
  });

  test('期望 nonce 但 token 里没有，同样拒绝', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims());
    await assert.rejects(() => auth.validateIdToken(token, { nonce: 'mine' }), /nonce mismatch/);
  });

  test('没发过 nonce 就不检查（非 OIDC 流程）', async () => {
    const auth = makeAuth();
    stubFetch();
    const token = await signIdToken(baseClaims());
    assert.ok(await auth.validateIdToken(token, { nonce: null }));
  });
});

describe('handleCallback 串起整条链路', () => {
  async function loginThenCallback(idTokenClaims, { tamperNonce = false } = {}) {
    const auth = makeAuth();
    stubFetch();
    await auth.login();

    const url = new URL(redirectedTo);
    const state = url.searchParams.get('state');
    const nonce = url.searchParams.get('nonce');

    const idToken = await signIdToken(
      baseClaims({ nonce: tamperNonce ? 'attacker-nonce' : nonce, ...idTokenClaims }),
    );
    stubFetch([{ body: { access_token: 'AT', refresh_token: 'RT', expires_in: 3600, id_token: idToken } }]);

    return { auth, run: () => auth.handleCallback('CODE', state) };
  }

  test('nonce 对得上时正常完成', async () => {
    const { run } = await loginThenCallback();
    const tokens = await run();
    assert.equal(tokens.access_token, 'AT');
  });

  test('ID Token 的 nonce 与本次请求不符时整个回调失败', async () => {
    const { run } = await loginThenCallback({}, { tamperNonce: true });
    await assert.rejects(run, /nonce mismatch/);
  });

  test('回调结束后 nonce 被清掉，不能重复使用', async () => {
    const { auth, run } = await loginThenCallback();
    await run();
    assert.equal(session.getItem(auth.keys.nonce), null);
  });

  test('没有 id_token 时不做 ID Token 校验（纯 OAuth 流程）', async () => {
    const auth = makeAuth('profile');
    stubFetch();
    await auth.login();
    const state = new URL(redirectedTo).searchParams.get('state');
    stubFetch([{ body: { access_token: 'AT', expires_in: 3600 } }]);
    assert.equal((await auth.handleCallback('CODE', state)).access_token, 'AT');
  });
});

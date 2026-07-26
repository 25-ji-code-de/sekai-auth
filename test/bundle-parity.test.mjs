/*
 * Copyright 2026 The 25-ji-code-de Team
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * IIFE 产物与 ESM 源码的等价性测试。
 *
 * dist/sekai-auth.global.js 是 scripts/build.mjs **用正则**从 src/index.js
 * 剥掉 export 关键字生成的。这是整个包里最脆的一环：正则漏掉一种声明形式
 * （比如最初就漏了 `export async function`），产物就会静默地与源码不一致，
 * 而 nightcord 与 25ji-sagyo 这两个生产前端直接依赖这个产物。
 *
 * 所以这里不只测"能加载"，而是把关键行为在**两个产物上各跑一遍**并断言结果相同。
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

import * as esm from '../src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE = join(root, 'dist', 'sekai-auth.global.js');

/** 在隔离的 vm context 里求值 IIFE 产物，取回它挂上的全局命名空间。 */
function loadBundle() {
  const sandbox = {
    console,
    crypto,
    TextEncoder,
    URLSearchParams,
    URL,
    btoa,
    Date,
    Number,
    Math,
    JSON,
    Promise,
    Error,
    Array,
    Object,
    String,
    Uint8Array,
    fetch: async () => {
      throw new Error('unexpected fetch');
    },
    location: { origin: 'https://app.example', search: '', href: '' },
    localStorage: null,
    sessionStorage: null,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  const context = vm.createContext(sandbox);
  vm.runInContext(readFileSync(BUNDLE, 'utf8'), context, { filename: 'sekai-auth.global.js' });
  return sandbox;
}

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

let bundle;
let iife;

before(() => {
  assert.ok(
    existsSync(BUNDLE),
    'dist/sekai-auth.global.js 不存在 —— 先跑 npm run build',
  );
  bundle = loadBundle();
  iife = bundle.SekaiAuthSDK;
});

describe('产物结构', () => {
  test('导出集合与 ESM 完全一致', () => {
    // ESM 的 default 是 SekaiAuth 的别名，IIFE 不需要它
    const esmNames = Object.keys(esm).filter((k) => k !== 'default').sort();
    const iifeNames = Object.keys(iife).sort();
    assert.deepEqual(iifeNames, esmNames);
  });

  test('保留 nightcord 依赖的旧全局名 SekaiPassAuth', () => {
    assert.equal(bundle.SekaiPassAuth, iife.SekaiAuth);
  });

  test('产物里不残留任何 module 语句', () => {
    const source = readFileSync(BUNDLE, 'utf8');
    const leftovers = source.match(/^\s*(export|import)\b.*$/gm) ?? [];
    assert.deepEqual(leftovers, [], `残留：${leftovers.join(' | ')}`);
  });
});

describe('纯函数在两个产物上结果相同', () => {
  test('base64UrlEncode', () => {
    for (const bytes of [[], [0], [251, 255, 190], [1, 2, 3, 4, 5]]) {
      const input = new Uint8Array(bytes);
      assert.equal(
        iife.base64UrlEncode(input),
        esm.base64UrlEncode(input),
        JSON.stringify(bytes),
      );
    }
  });

  test('base64UrlEncode 对大 buffer（分块路径）', () => {
    const big = new Uint8Array(200_000).fill(65);
    assert.equal(iife.base64UrlEncode(big), esm.base64UrlEncode(big));
  });

  test('computeCodeChallenge —— RFC 7636 测试向量', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const expected = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    // 这一条最关键：最初的 build 正则漏了 `export async function`，
    // 产物直接语法错误。等价断言能挡住同类回归。
    assert.equal(await iife.computeCodeChallenge(verifier), expected);
    assert.equal(await esm.computeCodeChallenge(verifier), expected);
  });

  test('randomHex 长度规则相同', () => {
    for (const n of [1, 16, 64]) {
      assert.equal(iife.randomHex(n).length, n * 2);
      assert.equal(esm.randomHex(n).length, esm.randomHex(n).length);
      assert.match(iife.randomHex(n), /^[0-9a-f]+$/);
    }
  });

  test('normalizeProfile 对同一输入产出相同结果', () => {
    const inputs = [
      null,
      {},
      { sub: 'u1', display_name: 'なこ', avatar_url: 'https://c/a.png', bio: ' x ' },
      { sub: 'u2', name: 'Asagi', picture: 'http://insecure/a.png' },
      { picture: 'javascript:alert(1)' },
      { preferred_username: 'nako', email: 'n@example.com' },
    ];
    for (const input of inputs) {
      const fromIife = iife.normalizeProfile(input);
      const fromEsm = esm.normalizeProfile(input);
      // 跨 realm：展开成当前 realm 的普通对象再比
      assert.deepEqual(
        fromIife && { ...fromIife },
        fromEsm && { ...fromEsm },
        JSON.stringify(input),
      );
    }
  });
});

describe('常量一致', () => {
  test('REFRESH_SKEW_MS 与 DEFAULT_EXPIRES_IN_S', () => {
    assert.equal(iife.REFRESH_SKEW_MS, esm.REFRESH_SKEW_MS);
    assert.equal(iife.DEFAULT_EXPIRES_IN_S, esm.DEFAULT_EXPIRES_IN_S);
  });

  test('SEKAI_PASS_ENDPOINTS 与 ISSUER', () => {
    assert.deepEqual({ ...iife.SEKAI_PASS_ENDPOINTS }, { ...esm.SEKAI_PASS_ENDPOINTS });
    assert.equal(iife.SEKAI_PASS_ISSUER, esm.SEKAI_PASS_ISSUER);
  });
});

describe('SekaiAuth 类行为一致', () => {
  const options = (storagePrefix, keys) => ({
    clientId: 'test_client',
    redirectUri: 'https://app.example/callback',
    endpoints: {
      authorize: 'https://id.example/oauth/authorize',
      token: 'https://id.example/oauth/token',
      userinfo: 'https://id.example/oauth/userinfo',
    },
    storagePrefix,
    keys,
    localStorage: new MemoryStorage(),
    sessionStorage: new MemoryStorage(),
  });

  test('默认 storage key 拼法相同（nightcord 用 sekai_pass_ 前缀）', () => {
    const a = new iife.SekaiAuth(options('sekai_pass_'));
    const b = new esm.SekaiAuth(options('sekai_pass_'));
    // 两边来自不同的 vm realm，原型不同 —— 展开到当前 realm 再比
    assert.deepEqual({ ...a.keys }, { ...b.keys });
    assert.equal(a.keys.accessToken, 'sekai_pass_access_token');
  });

  test('key 覆盖行为相同（25ji 用非默认的两个名字）', () => {
    const override = { expiresAt: 'sekai_token_expires_at', state: 'sekai_auth_state' };
    const a = new iife.SekaiAuth(options('sekai_', override));
    const b = new esm.SekaiAuth(options('sekai_', override));
    // 两边来自不同的 vm realm，原型不同 —— 展开到当前 realm 再比
    assert.deepEqual({ ...a.keys }, { ...b.keys });
    assert.equal(a.keys.expiresAt, 'sekai_token_expires_at');
  });

  test('isAuthenticated 判定一致', () => {
    const cases = [
      {},
      { access: 'AT' },
      { access: 'AT', expires: Date.now() + 60_000 },
      { access: 'AT', expires: Date.now() - 1 },
      { access: 'AT', refresh: 'RT', expires: Date.now() - 1 },
      { access: 'AT', expires: 'garbage' },
    ];
    for (const c of cases) {
      const build = (Ctor) => {
        const auth = new Ctor(options('sekai_'));
        if (c.access) auth._local.setItem(auth.keys.accessToken, c.access);
        if (c.refresh) auth._local.setItem(auth.keys.refreshToken, c.refresh);
        if (c.expires !== undefined) auth._local.setItem(auth.keys.expiresAt, String(c.expires));
        return auth.isAuthenticated();
      };
      assert.equal(build(iife.SekaiAuth), build(esm.SekaiAuth), JSON.stringify(c));
    }
  });

  test('构造校验抛出的错误类型一致', () => {
    assert.throws(() => new iife.SekaiAuth({}), iife.SekaiAuthError);
    assert.throws(() => new esm.SekaiAuth({}), esm.SekaiAuthError);
    assert.throws(() => new iife.SekaiAuth({ clientId: 'x' }), /endpoints|issuer/);
    assert.throws(() => new esm.SekaiAuth({ clientId: 'x' }), /endpoints|issuer/);
  });

  test('SekaiAuthError 的 code / status 字段一致', () => {
    const a = new iife.SekaiAuthError('boom', { code: 'invalid_state', status: 400 });
    const b = new esm.SekaiAuthError('boom', { code: 'invalid_state', status: 400 });
    assert.equal(a.name, b.name);
    assert.equal(a.code, b.code);
    assert.equal(a.status, b.status);
    assert.equal(a.message, b.message);
  });
});

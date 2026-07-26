# @25-ji-code-de/sekai-auth

SEKAI Pass 浏览器端 OAuth 2.1 + PKCE 客户端。零依赖，只用 WebCrypto 和 `fetch`。

这个包取代了生态里四份各自漂移的实现：`hub/assets/js/auth.js`、`25ji-sagyo/js/utils/auth.js`、`nightcord/sekai-pass-auth.js`、`stickers-maker/src/services/auth.service.ts`。

## 安装

```bash
npm install @25-ji-code-de/sekai-auth
```

`<script>` 直接引也行（IIFE 产物挂在 `window.SekaiAuthSDK`）：

```html
<script src="/vendor/sekai-auth.global.js"></script>
```

## 用法

### ESM

```js
import { createSekaiAuth, SEKAI_PASS_ENDPOINTS } from '@25-ji-code-de/sekai-auth';

const auth = createSekaiAuth({
  clientId: 'hub_client',
  redirectUri: `${location.origin}/callback`,
  endpoints: SEKAI_PASS_ENDPOINTS,
});

if (!auth.isAuthenticated()) await auth.login();
```

回调页：

```js
// 不传参时自动从 location.search 读 code / state / error
await auth.handleCallback();
location.replace('/');
```

带认证的请求：

```js
const token = await auth.getAccessToken();  // 需要时自动刷新
if (!token) return auth.login();

await fetch('https://api.nightcord.de5.net/user/stats', {
  headers: { Authorization: `Bearer ${token}` },
});
```

### 走 OIDC discovery

给 `issuer` 代替 `endpoints`，端点从 `/.well-known/openid-configuration` 解析并缓存：

```js
const auth = createSekaiAuth({
  clientId: import.meta.env.VITE_OAUTH_CLIENT_ID,
  issuer: 'https://id.nightcord.de5.net',
});
```

## OIDC：nonce 与 ID Token 验证

`scope` 含 `openid` 时，`login()` 会自动生成 `nonce` 一并发出，回调里如果拿到
`id_token` 就自动验证 —— **签名、`iss`、`aud`、`exp`、`iat`，以及 `nonce` 是否
就是本次请求发出的那一个**。任一项不过就抛错，不会把 token 交出去。

```js
// 什么都不用做，走 handleCallback 就已经验过了
const tokens = await auth.handleCallback();
```

nonce 挡的是**ID Token 注入**：攻击者把在别处（别的用户、别的会话）拿到的合法
ID Token 塞进你的回调。`state` 只能保证「这次回调对应我发起的那次请求」，而
`nonce` 写在 ID Token 内部、由签发方带回，所以能进一步保证「这个 ID Token 就是
为这次请求签的」。

> 单验 nonce 是没有意义的 —— 能注入 token 的攻击者同样能伪造 nonce。
> 所以必须连签名一起验，两步缺一不可。SDK 里这两步绑在一起，不提供只验其一的开关。

签名走 issuer 的 JWKS（discovery 的 `jwks_uri`，没有就按
`<issuer>/.well-known/jwks.json` 推），结果缓存，一次会话只拉一次。

**只接受 ES256 与 RS256。** `alg: none` 和一切对称算法（HS256 等）直接拒绝 ——
后者会让「把 JWKS 里的公钥当成 HMAC 密钥」的经典伪造攻击成立。

需要手工验时：

```js
const claims = await auth.validateIdToken(idToken, {
  nonce: 'n1',        // 省略或 null 表示不检查这一项
  clockSkewSec: 60,   // 时钟容差，默认 60 秒
});
```

另外有个 `decodeJwtPayload(token)`，**不验签**，只解 payload，输入畸形返回 `null`。
它只适合读展示用的 claim，任何安全判断都要走 `validateIdToken()`。

## 行为约定

这些是生态内所有前端必须一致的行为，SDK 已内建：

| 约定 | 值 |
|---|---|
| PKCE method | `S256`，`code_verifier` 为 64 随机字节 → 128 hex 字符（RFC 7636 上限）|
| 临时机密存放 | `sessionStorage`（标签页作用域）|
| token 存放 | `localStorage` |
| 提前刷新 | 距过期 < 5 分钟即刷新 |
| `expires_in` 缺省 | 按 3600 秒处理 |
| 并发刷新 | single-flight，多个调用共享同一请求 |
| `state` | 一次性，读出即作废，重放会被拒 |
| `nonce` | `scope` 含 `openid` 时自动生成并校验；回调后即清除 |
| ID Token 签名算法 | 只接受 `ES256` / `RS256`；`alg: none` 与对称算法拒绝 |
| refresh 失败 | 清空本地状态，返回 `null`，触发 `onAuthExpired` |
| 登出 | best-effort `POST /oauth/revoke`（RFC 7009，`keepalive`），再清本地 |
| `isAuthenticated()` | 有 refresh token 时即使 access 过期也算已登录 |

## Storage key

默认由 `storagePrefix`（默认 `sekai_`）拼出：

```
sekai_access_token  sekai_refresh_token  sekai_expires_at  sekai_user
sekai_code_verifier  sekai_state  sekai_nonce   （后三个在 sessionStorage）
```

既有部署的 key 不一致，可以逐项覆盖，**避免升级后把用户登出**：

```js
// hub / 25ji-sagyo 的历史 key
createSekaiAuth({
  storagePrefix: 'sekai_',
  keys: { expiresAt: 'sekai_token_expires_at', state: 'sekai_auth_state' },
});

// nightcord 的历史 key —— 默认值刚好对得上
createSekaiAuth({ storagePrefix: 'sekai_pass_' });
```

## API

| 成员 | 说明 |
|---|---|
| `login()` | 生成 PKCE 参数并跳转授权端点 |
| `handleCallback(code?, state?)` | 换取 token；省略参数时从 `location.search` 读；带 `id_token` 时自动验证 |
| `validateIdToken(idToken, { nonce, clockSkewSec })` | 验签 + `iss` / `aud` / `exp` / `iat` / `nonce`，返回 claim |
| `getAccessToken()` | 返回有效 token，必要时刷新；失败返回 `null` |
| `refresh()` | 手动刷新（single-flight）|
| `getUserInfo({ cache })` | 拉 userinfo；`cache: true` 时写入 localStorage |
| `getCachedUser()` | 读缓存的 userinfo，不发请求 |
| `normalizeProfile(userInfo)` | 归一 SEKAI Pass / OIDC 字段差异 |
| `decodeJwtPayload(token)` | **不验签**解出 payload，畸形返回 `null`；仅供展示 |
| `isAuthenticated()` | 纯本地判断 |
| `logout({ redirectTo, revoke })` | 撤销 + 清本地 |
| `getEndpoints()` | 解析后的端点（discovery 时会触发一次请求）|

失败抛 `SekaiAuthError`，带 `code`（OAuth error code 或 `invalid_state` / `discovery_failed` / `network_error` 等）和 `status`。

注意 `getAccessToken()` 和 `getUserInfo()` **不抛异常**，失败返回 `null` —— 调用方据此引导重新登录。会抛的是 `login()` / `handleCallback()` / `refresh()` 链路上的配置与协议错误。

## `normalizeProfile`

SEKAI Pass 的 userinfo 用 `display_name` / `username` / `avatar_url`，标准 OIDC 用 `name` / `preferred_username` / `picture`。这个函数两边都认，输出稳定结构：

```js
{ sub, displayName, username, avatarUrl, bio }
```

`avatarUrl` 只接受 `https:` 开头的值，其余一律为 `null`（防止 userinfo 被污染时注入 `javascript:` / `data:`）。

## 开发

```bash
npm test     # node:test，无需安装依赖
npm run build  # 产出 dist/sekai-auth.mjs 与 dist/sekai-auth.global.js
```

## 许可证

Apache-2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

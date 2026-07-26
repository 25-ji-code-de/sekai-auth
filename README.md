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
| refresh 失败 | 清空本地状态，返回 `null`，触发 `onAuthExpired` |
| 登出 | best-effort `POST /oauth/revoke`（RFC 7009，`keepalive`），再清本地 |
| `isAuthenticated()` | 有 refresh token 时即使 access 过期也算已登录 |

## Storage key

默认由 `storagePrefix`（默认 `sekai_`）拼出：

```
sekai_access_token  sekai_refresh_token  sekai_expires_at  sekai_user
sekai_code_verifier  sekai_state          （后两个在 sessionStorage）
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
| `handleCallback(code?, state?)` | 换取 token；省略参数时从 `location.search` 读 |
| `getAccessToken()` | 返回有效 token，必要时刷新；失败返回 `null` |
| `refresh()` | 手动刷新（single-flight）|
| `getUserInfo({ cache })` | 拉 userinfo；`cache: true` 时写入 localStorage |
| `getCachedUser()` | 读缓存的 userinfo，不发请求 |
| `normalizeProfile(userInfo)` | 归一 SEKAI Pass / OIDC 字段差异 |
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

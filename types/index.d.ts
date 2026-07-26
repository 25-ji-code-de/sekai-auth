/*
 * Copyright 2026 The 25-ji-code-de Team
 * SPDX-License-Identifier: Apache-2.0
 */

/** 提前多久刷新 access token（生态约定：5 分钟）。 */
export const REFRESH_SKEW_MS: number;

/** `expires_in` 缺省时按 1 小时处理。 */
export const DEFAULT_EXPIRES_IN_S: number;

/**
 * 从 `byteLength` 个随机字节生成 hex 串。
 * 注意返回长度是 `2 * byteLength` 个字符。
 */
export function randomHex(byteLength: number): string;

/** Base64URL 编码（无 padding）。 */
export function base64UrlEncode(buffer: ArrayBuffer | Uint8Array): string;

/** 由 code_verifier 计算 S256 code_challenge。 */
export function computeCodeChallenge(verifier: string): Promise<string>;

/** 归一化后的用户 profile。 */
export interface SekaiProfile {
  sub: string | null;
  displayName: string;
  username: string;
  /** 只接受 https 开头的值，其余为 null。 */
  avatarUrl: string | null;
  bio: string;
}

/**
 * 把 SEKAI Pass userinfo / OIDC claim 归一成稳定结构。
 *
 * SEKAI Pass 用 `display_name` / `username` / `avatar_url`，
 * 标准 OIDC 用 `name` / `preferred_username` / `picture`；两边都认。
 */
export function normalizeProfile(userInfo: Record<string, unknown> | null): SekaiProfile | null;

export interface SekaiAuthErrorOptions {
  code?: string;
  status?: number;
  cause?: unknown;
}

/** OAuth / 网络错误的统一异常类型。 */
export class SekaiAuthError extends Error {
  constructor(message: string, options?: SekaiAuthErrorOptions);
  name: 'SekaiAuthError';
  /** OAuth error code，或 `invalid_state` / `discovery_failed` / `network_error` 等。 */
  code: string;
  status?: number;
}

export interface SekaiEndpoints {
  authorize: string;
  token: string;
  userinfo: string;
  revoke?: string;
}

/** storage key 后缀，可逐项覆盖以对齐既有部署。 */
export interface SekaiStorageKeys {
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: string;
  user?: string;
  codeVerifier?: string;
  state?: string;
}

export interface SekaiAuthOptions {
  clientId: string;
  /** 默认 `${location.origin}/callback`。 */
  redirectUri?: string;
  /** 默认 `openid profile email`。 */
  scope?: string;
  /** 与 `issuer` 二选一。 */
  endpoints?: SekaiEndpoints;
  /** 与 `endpoints` 二选一；走 OIDC discovery。 */
  issuer?: string;
  /** 默认 `sekai_`。 */
  storagePrefix?: string;
  /** 逐项覆盖 storage key，避免迁移时把现有用户登出。 */
  keys?: SekaiStorageKeys;
  /** refresh token 失效时触发。 */
  onAuthExpired?: (error?: unknown) => void;
  localStorage?: Storage;
  sessionStorage?: Storage;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number | string;
  token_type?: string;
  scope?: string;
  [key: string]: unknown;
}

export interface LogoutOptions {
  /** 给了就跳转。 */
  redirectTo?: string;
  /** 默认 true。 */
  revoke?: boolean;
}

/** SEKAI Pass OAuth 2.1 + PKCE 客户端。 */
export class SekaiAuth {
  constructor(options: SekaiAuthOptions);

  clientId: string;
  redirectUri: string;
  scope: string;
  issuer?: string;
  /** 解析后的完整 storage key（含前缀）。 */
  readonly keys: Required<SekaiStorageKeys>;

  /** 解析端点；配了 `issuer` 时会触发一次 discovery 并缓存。 */
  getEndpoints(): Promise<SekaiEndpoints>;

  /** 生成 PKCE 参数并跳转授权端点。 */
  login(): Promise<void>;

  /** 换取 token。省略参数时从 `location.search` 读 code / state / error。 */
  handleCallback(code?: string, state?: string): Promise<TokenResponse>;

  /** 返回有效 access token，必要时自动刷新；失败返回 `null`（不抛）。 */
  getAccessToken(): Promise<string | null>;

  /** 手动刷新（single-flight）；失败返回 `null`。 */
  refresh(): Promise<string | null>;

  /** 拉 userinfo；未登录或失败返回 `null`（不抛）。 */
  getUserInfo(options?: { cache?: boolean }): Promise<Record<string, unknown> | null>;

  /** 读 `getUserInfo({ cache: true })` 缓存的结果，不发请求。 */
  getCachedUser(): Record<string, unknown> | null;

  normalizeProfile(userInfo: Record<string, unknown> | null): SekaiProfile | null;

  /** 纯本地判断；有 refresh token 时即使 access 过期也算已登录。 */
  isAuthenticated(): boolean;

  /** best-effort RFC 7009 revoke，再清本地。 */
  logout(options?: LogoutOptions): Promise<void>;
}

/** 等价于 `new SekaiAuth(options)`。 */
export function createSekaiAuth(options: SekaiAuthOptions): SekaiAuth;

/** SEKAI Pass 生产环境端点。 */
export const SEKAI_PASS_ENDPOINTS: Readonly<SekaiEndpoints>;

export const SEKAI_PASS_ISSUER: string;

export default SekaiAuth;

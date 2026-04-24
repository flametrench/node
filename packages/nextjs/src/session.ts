// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type {
  CredId,
  IdentityStore,
  Session,
  UsrId,
} from "@flametrench/identity";

import type { CookieAccessor } from "./cookies.js";
import { UnauthenticatedError } from "./errors.js";

/**
 * Cookie configuration. Defaults match common best practice for session
 * cookies: HttpOnly (no JS access), Secure in production, SameSite=Lax
 * (allows top-level navigations from external links to retain auth).
 */
export interface SessionCookieOptions {
  /** Cookie name. Default: `flametrench_session`. */
  name?: string;
  /** Send only over HTTPS. Default: `true` when `NODE_ENV === 'production'`, else `false`. */
  secure?: boolean;
  /** SameSite policy. Default: `lax`. */
  sameSite?: "strict" | "lax" | "none";
  /** Cookie path. Default: `/`. */
  path?: string;
  /** Optional cookie domain (e.g. `.flametrench.dev` for cross-subdomain). */
  domain?: string;
  /** TTL for newly-issued session cookies. Default: 7 days. */
  defaultTtlSeconds?: number;
}

/** Resolved cookie defaults, with all fields filled. */
interface ResolvedCookieOptions {
  name: string;
  secure: boolean;
  sameSite: "strict" | "lax" | "none";
  path: string;
  domain: string | undefined;
  defaultTtlSeconds: number;
}

function resolveCookieOptions(
  overrides: SessionCookieOptions | undefined,
): ResolvedCookieOptions {
  return {
    name: overrides?.name ?? "flametrench_session",
    secure: overrides?.secure ?? process.env.NODE_ENV === "production",
    sameSite: overrides?.sameSite ?? "lax",
    path: overrides?.path ?? "/",
    domain: overrides?.domain,
    defaultTtlSeconds: overrides?.defaultTtlSeconds ?? 7 * 24 * 60 * 60,
  };
}

/**
 * Configuration for the Next adapter. The store is the source of truth;
 * the cookies accessor is what we use to read/write the bearer cookie.
 */
export interface FlametrenchNextConfig {
  identityStore: IdentityStore;
  cookies: CookieAccessor;
  cookieOptions?: SessionCookieOptions;
}

/**
 * Helper bundle returned by `createFlametrenchNext`. Every method is
 * bound to the supplied configuration so callers don't need to thread it
 * through manually.
 */
export interface FlametrenchNextHelpers {
  /**
   * Read the bearer cookie, verify it against the identity store, and
   * return the active session — or `null` if no cookie or invalid token.
   */
  getSession(): Promise<Session | null>;

  /**
   * Like `getSession` but throws `UnauthenticatedError` if no valid session.
   * Use in server components / route handlers that require auth.
   */
  requireSession(): Promise<Session>;

  /**
   * Authenticate with a password, create a new session, and set the
   * bearer cookie. Returns the resulting session.
   */
  signInWithPassword(input: {
    identifier: string;
    password: string;
    ttlSeconds?: number;
  }): Promise<Session>;

  /**
   * Create a session for an already-verified credential. Useful when
   * verification was performed via passkey/OIDC outside this adapter.
   */
  createSession(input: {
    usrId: UsrId;
    credId: CredId;
    ttlSeconds?: number;
  }): Promise<Session>;

  /**
   * Rotate the current session: issue a new session id + token, mark the
   * previous session terminal, replace the cookie. No-op if no current
   * session.
   */
  refreshSession(): Promise<Session | null>;

  /**
   * Revoke the current session and clear the cookie. Idempotent.
   */
  signOut(): Promise<void>;
}

/**
 * Build the Next.js helper bundle for a given identity store.
 *
 * @example
 *     // app/_lib/flametrench.ts
 *     import { cookies } from "next/headers";
 *     import { InMemoryIdentityStore } from "@flametrench/identity";
 *     import { createFlametrenchNext } from "@flametrench/nextjs";
 *
 *     const identityStore = new InMemoryIdentityStore();
 *     export const flametrench = createFlametrenchNext({
 *       identityStore,
 *       cookies,
 *     });
 *
 *     // app/page.tsx (a server component)
 *     import { flametrench } from "./_lib/flametrench";
 *     export default async function Page() {
 *       const session = await flametrench.getSession();
 *       return session ? <Authed /> : <Anon />;
 *     }
 */
export function createFlametrenchNext(
  config: FlametrenchNextConfig,
): FlametrenchNextHelpers {
  const opts = resolveCookieOptions(config.cookieOptions);
  const accessor = config.cookies;
  const store = config.identityStore;

  async function readCookieToken(): Promise<string | null> {
    const cookieStore = await accessor();
    const c = cookieStore.get(opts.name);
    return c?.value ?? null;
  }

  async function writeCookie(token: string, expiresAt: Date): Promise<void> {
    const cookieStore = await accessor();
    cookieStore.set(opts.name, token, {
      httpOnly: true,
      secure: opts.secure,
      sameSite: opts.sameSite,
      path: opts.path,
      domain: opts.domain,
      expires: expiresAt,
    });
  }

  async function deleteCookie(): Promise<void> {
    const cookieStore = await accessor();
    cookieStore.delete(opts.name);
  }

  async function getSession(): Promise<Session | null> {
    const token = await readCookieToken();
    if (!token) return null;
    try {
      return await store.verifySessionToken(token);
    } catch {
      // Token is invalid / expired / revoked. Treat as anonymous.
      // Best-effort cookie cleanup so subsequent requests don't keep
      // re-attempting verification.
      await deleteCookie().catch(() => {});
      return null;
    }
  }

  async function requireSession(): Promise<Session> {
    const session = await getSession();
    if (!session) throw new UnauthenticatedError();
    return session;
  }

  async function signInWithPassword(input: {
    identifier: string;
    password: string;
    ttlSeconds?: number;
  }): Promise<Session> {
    const verified = await store.verifyPassword({
      type: "password",
      identifier: input.identifier,
      password: input.password,
    });
    return createSession({
      usrId: verified.usrId,
      credId: verified.credId,
      ttlSeconds: input.ttlSeconds,
    });
  }

  async function createSession(input: {
    usrId: UsrId;
    credId: CredId;
    ttlSeconds?: number;
  }): Promise<Session> {
    const ttlSeconds = input.ttlSeconds ?? opts.defaultTtlSeconds;
    const { session, token } = await store.createSession({
      usrId: input.usrId,
      credId: input.credId,
      ttlSeconds,
    });
    await writeCookie(token, session.expiresAt);
    return session;
  }

  async function refreshSession(): Promise<Session | null> {
    const current = await getSession();
    if (!current) return null;
    const { session, token } = await store.refreshSession(current.id);
    await writeCookie(token, session.expiresAt);
    return session;
  }

  async function signOut(): Promise<void> {
    const current = await getSession();
    if (current) {
      try {
        await store.revokeSession(current.id);
      } catch {
        // Already revoked / expired — fine.
      }
    }
    await deleteCookie();
  }

  return {
    getSession,
    requireSession,
    signInWithPassword,
    createSession,
    refreshSession,
    signOut,
  };
}

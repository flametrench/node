// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it } from "vitest";

import { InMemoryIdentityStore, type UsrId, type CredId } from "@flametrench/identity";

import {
  createFlametrenchNext,
  makeAuthRouteHandlers,
  UnauthenticatedError,
  type CookieStore,
  type FlametrenchNextHelpers,
} from "../src/index.js";

/**
 * Fake CookieStore that mimics Next.js's `cookies()` return shape just
 * enough for the adapter. Stores values in memory; ignores secure / domain
 * flags (they don't affect verification logic).
 */
function makeFakeCookieStore() {
  const store = new Map<string, { name: string; value: string }>();
  const fake: CookieStore = {
    get: (name) => store.get(name),
    set: (name, value) => {
      store.set(name, { name, value });
    },
    delete: (name) => {
      store.delete(name);
    },
  };
  return { fake, raw: store };
}

describe("@flametrench/nextjs", () => {
  let identityStore: InMemoryIdentityStore;
  let cookies: ReturnType<typeof makeFakeCookieStore>;
  let helpers: FlametrenchNextHelpers;

  // Helpers to set up an authenticatable user.
  let aliceUsr: UsrId;
  let aliceCred: CredId;

  beforeEach(async () => {
    identityStore = new InMemoryIdentityStore();
    cookies = makeFakeCookieStore();
    helpers = createFlametrenchNext({
      identityStore,
      cookies: () => cookies.fake,
      cookieOptions: {
        // Force `secure: false` so tests don't depend on NODE_ENV.
        secure: false,
      },
    });
    const user = await identityStore.createUser();
    aliceUsr = user.id;
    const cred = await identityStore.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "correcthorsebatterystaple",
    });
    aliceCred = cred.id;
  });

  // ───────── getSession / requireSession ─────────

  describe("getSession / requireSession", () => {
    it("returns null when no cookie is set", async () => {
      expect(await helpers.getSession()).toBeNull();
    });

    it("requireSession throws UnauthenticatedError when not signed in", async () => {
      await expect(helpers.requireSession()).rejects.toThrow(UnauthenticatedError);
    });

    it("returns null when cookie holds an unknown token (and clears the cookie)", async () => {
      cookies.fake.set("flametrench_session", "not-a-real-token", {});
      expect(await helpers.getSession()).toBeNull();
      // Adapter cleared the bad cookie.
      expect(cookies.fake.get("flametrench_session")).toBeUndefined();
    });
  });

  // ───────── signInWithPassword ─────────

  describe("signInWithPassword", () => {
    it("creates a session and writes the bearer cookie", async () => {
      const session = await helpers.signInWithPassword({
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      expect(session.usrId).toBe(aliceUsr);
      expect(session.credId).toBe(aliceCred);
      const cookie = cookies.fake.get("flametrench_session");
      expect(cookie).toBeDefined();
      // Cookie value is the bearer token, NOT the session id (per spec).
      expect(cookie!.value).not.toBe(session.id);
      expect(cookie!.value.length).toBeGreaterThanOrEqual(32);
    });

    it("subsequent getSession returns the live session", async () => {
      await helpers.signInWithPassword({
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const got = await helpers.getSession();
      expect(got).not.toBeNull();
      expect(got!.usrId).toBe(aliceUsr);
    });

    it("rejects an invalid password", async () => {
      await expect(
        helpers.signInWithPassword({
          identifier: "alice@example.com",
          password: "wrong",
        }),
      ).rejects.toThrow();
      // No cookie set on failure.
      expect(cookies.fake.get("flametrench_session")).toBeUndefined();
    });
  });

  // ───────── refreshSession ─────────

  describe("refreshSession", () => {
    it("rotates: new session id, new cookie token, old session marked terminal", async () => {
      const first = await helpers.signInWithPassword({
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const oldToken = cookies.fake.get("flametrench_session")!.value;

      const refreshed = await helpers.refreshSession();
      expect(refreshed).not.toBeNull();
      expect(refreshed!.id).not.toBe(first.id);

      const newToken = cookies.fake.get("flametrench_session")!.value;
      expect(newToken).not.toBe(oldToken);

      // Old session is now terminal.
      const oldFetched = await identityStore.getSession(first.id);
      expect(oldFetched.revokedAt).not.toBeNull();
    });

    it("returns null when no session is active", async () => {
      const result = await helpers.refreshSession();
      expect(result).toBeNull();
    });
  });

  // ───────── signOut ─────────

  describe("signOut", () => {
    it("revokes the current session and clears the cookie", async () => {
      const session = await helpers.signInWithPassword({
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      await helpers.signOut();
      expect(cookies.fake.get("flametrench_session")).toBeUndefined();
      const fetched = await identityStore.getSession(session.id);
      expect(fetched.revokedAt).not.toBeNull();
    });

    it("is idempotent when no session is active", async () => {
      // Should not throw.
      await helpers.signOut();
    });
  });

  // ───────── createSession (already-verified path) ─────────

  describe("createSession", () => {
    it("creates a session for an already-verified credential", async () => {
      const session = await helpers.createSession({
        usrId: aliceUsr,
        credId: aliceCred,
        ttlSeconds: 3600,
      });
      expect(session.usrId).toBe(aliceUsr);
      expect(cookies.fake.get("flametrench_session")).toBeDefined();
    });
  });

  // ───────── Route handlers ─────────

  describe("makeAuthRouteHandlers", () => {
    it("signIn POST with valid credentials returns 200 + sets cookie", async () => {
      const { POST } = makeAuthRouteHandlers(helpers).signIn();
      const req = new Request("http://localhost/api/auth/sign-in", {
        method: "POST",
        body: JSON.stringify({
          identifier: "alice@example.com",
          password: "correcthorsebatterystaple",
        }),
      });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { session: { usrId: string } };
      expect(body.session.usrId).toBe(aliceUsr);
      expect(cookies.fake.get("flametrench_session")).toBeDefined();
    });

    it("signIn POST with bad credentials returns 401", async () => {
      const { POST } = makeAuthRouteHandlers(helpers).signIn();
      const req = new Request("http://localhost/api/auth/sign-in", {
        method: "POST",
        body: JSON.stringify({
          identifier: "alice@example.com",
          password: "wrong",
        }),
      });
      const res = await POST(req);
      expect(res.status).toBe(401);
    });

    it("signIn POST with malformed body returns 400", async () => {
      const { POST } = makeAuthRouteHandlers(helpers).signIn();
      const req = new Request("http://localhost/api/auth/sign-in", {
        method: "POST",
        body: "not json",
      });
      const res = await POST(req);
      expect(res.status).toBe(400);
    });

    it("me GET returns 401 when no session, 200 when signed in", async () => {
      const { GET } = makeAuthRouteHandlers(helpers).me();
      const noSession = await GET();
      expect(noSession.status).toBe(401);

      await helpers.signInWithPassword({
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const withSession = await GET();
      expect(withSession.status).toBe(200);
    });

    it("signOut POST is idempotent and returns 200", async () => {
      const { POST } = makeAuthRouteHandlers(helpers).signOut();
      const res = await POST();
      expect(res.status).toBe(200);
    });

    it("refresh POST rotates the active session", async () => {
      await helpers.signInWithPassword({
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const oldToken = cookies.fake.get("flametrench_session")!.value;
      const { POST } = makeAuthRouteHandlers(helpers).refresh();
      const res = await POST();
      expect(res.status).toBe(200);
      const newToken = cookies.fake.get("flametrench_session")!.value;
      expect(newToken).not.toBe(oldToken);
    });

    it("refresh POST returns 401 when no session", async () => {
      const { POST } = makeAuthRouteHandlers(helpers).refresh();
      const res = await POST();
      expect(res.status).toBe(401);
    });
  });

  // ───────── Cookie name customization ─────────

  describe("cookieOptions.name", () => {
    it("uses a custom cookie name when configured", async () => {
      const customCookies = makeFakeCookieStore();
      const customHelpers = createFlametrenchNext({
        identityStore,
        cookies: () => customCookies.fake,
        cookieOptions: { name: "session_v2", secure: false },
      });
      await customHelpers.signInWithPassword({
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      expect(customCookies.fake.get("session_v2")).toBeDefined();
      expect(customCookies.fake.get("flametrench_session")).toBeUndefined();
    });
  });
});

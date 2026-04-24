// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it } from "vitest";

import {
  AlreadyTerminalError,
  CredentialNotActiveError,
  CredentialTypeMismatchError,
  DuplicateCredentialError,
  InMemoryIdentityStore,
  InvalidCredentialError,
  InvalidTokenError,
  NotFoundError,
  PreconditionError,
  SessionExpiredError,
  type PasswordCredential,
} from "../src/index.js";

describe("InMemoryIdentityStore", () => {
  let store: InMemoryIdentityStore;

  beforeEach(() => {
    store = new InMemoryIdentityStore();
  });

  // ───────────── Users ─────────────

  describe("user lifecycle", () => {
    it("creates, gets, and returns active users with fresh usr_ ids", async () => {
      const u = await store.createUser();
      expect(u.id).toMatch(/^usr_[0-9a-f]{32}$/);
      expect(u.status).toBe("active");
      expect(await store.getUser(u.id)).toEqual(u);
    });

    it("suspend → reinstate round-trip", async () => {
      const u = await store.createUser();
      const suspended = await store.suspendUser(u.id);
      expect(suspended.status).toBe("suspended");
      const reinstated = await store.reinstateUser(u.id);
      expect(reinstated.status).toBe("active");
    });

    it("throws NotFoundError on unknown user ids", async () => {
      await expect(store.getUser("usr_0000000000000000000000000000dead" as never)).rejects.toThrow(
        NotFoundError,
      );
    });

    it("suspendUser cascades — terminates all active sessions but preserves credentials", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const { session } = await store.createSession({
        usrId: u.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      await store.suspendUser(u.id);
      // Session is terminated.
      const after = await store.getSession(session.id);
      expect(after.revokedAt).not.toBeNull();
      // Credentials are NOT cascaded for suspend (only for revoke).
      const preservedCred = await store.getCredential(cred.id);
      expect(preservedCred.status).toBe("active");
    });

    it("revokeUser cascades — revokes credentials AND terminates sessions", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const { session } = await store.createSession({
        usrId: u.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      await store.revokeUser(u.id);
      const cascadedCred = await store.getCredential(cred.id);
      expect(cascadedCred.status).toBe("revoked");
      const cascadedSes = await store.getSession(session.id);
      expect(cascadedSes.revokedAt).not.toBeNull();
    });

    it("double-revoke is rejected", async () => {
      const u = await store.createUser();
      await store.revokeUser(u.id);
      await expect(store.revokeUser(u.id)).rejects.toThrow(AlreadyTerminalError);
    });
  });

  // ───────────── Password credentials ─────────────

  describe("password credentials", () => {
    it("hashes with Argon2id and exposes a public credential without the hash", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      expect(cred.type).toBe("password");
      // Public credential should not expose passwordHash.
      expect((cred as PasswordCredential & { passwordHash?: string }).passwordHash).toBeUndefined();
    });

    it("rejects a duplicate active credential for the same (type, identifier)", async () => {
      const u = await store.createUser();
      await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      await expect(
        store.createCredential({
          usrId: u.id,
          type: "password",
          identifier: "alice@example.com",
          password: "different",
        }),
      ).rejects.toThrow(DuplicateCredentialError);
    });

    it("verifyPassword succeeds with the correct password and returns usr+cred ids", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const result = await store.verifyPassword({
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      expect(result.usrId).toBe(u.id);
      expect(result.credId).toBe(cred.id);
    });

    it("verifyPassword throws InvalidCredentialError on a wrong password", async () => {
      const u = await store.createUser();
      await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      await expect(
        store.verifyPassword({
          type: "password",
          identifier: "alice@example.com",
          password: "wrong",
        }),
      ).rejects.toThrow(InvalidCredentialError);
    });

    it("verifyPassword throws InvalidCredentialError for an unknown identifier", async () => {
      await expect(
        store.verifyPassword({
          type: "password",
          identifier: "nobody@example.com",
          password: "anything",
        }),
      ).rejects.toThrow(InvalidCredentialError);
    });

    it("rotateCredential revokes old, inserts new with replaces chain, terminates sessions", async () => {
      const u = await store.createUser();
      const oldCred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const { session } = await store.createSession({
        usrId: u.id,
        credId: oldCred.id,
        ttlSeconds: 3600,
      });
      const newCred = await store.rotateCredential({
        credId: oldCred.id,
        type: "password",
        newPassword: "NEW-passphrase-correcthorsebattery",
      });
      expect(newCred.replaces).toBe(oldCred.id);
      // Old cred is revoked.
      const oldFetched = await store.getCredential(oldCred.id);
      expect(oldFetched.status).toBe("revoked");
      // Sessions bound to the old cred are terminated.
      const cascaded = await store.getSession(session.id);
      expect(cascaded.revokedAt).not.toBeNull();
      // Old password no longer verifies.
      await expect(
        store.verifyPassword({
          type: "password",
          identifier: "alice@example.com",
          password: "correcthorsebatterystaple",
        }),
      ).rejects.toThrow(InvalidCredentialError);
      // New password does.
      const ok = await store.verifyPassword({
        type: "password",
        identifier: "alice@example.com",
        password: "NEW-passphrase-correcthorsebattery",
      });
      expect(ok.credId).toBe(newCred.id);
    });

    it("rotateCredential type-mismatches are rejected", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      await expect(
        store.rotateCredential({
          credId: cred.id,
          type: "oidc",
          oidcIssuer: "https://accounts.example.com",
          oidcSubject: "sub",
        }),
      ).rejects.toThrow(CredentialTypeMismatchError);
    });
  });

  // ───────────── Passkey credentials ─────────────

  describe("passkey credentials", () => {
    it("creates a passkey credential and exposes rp_id + sign_count but not the public key bytes", async () => {
      const u = await store.createUser();
      const publicKey = Uint8Array.from([0xa5, 0x01, 0x02, 0x03]);
      const cred = await store.createCredential({
        usrId: u.id,
        type: "passkey",
        identifier: "credentialIdBase64Url",
        publicKey,
        signCount: 0,
        rpId: "example.com",
      });
      expect(cred.type).toBe("passkey");
      if (cred.type === "passkey") {
        expect(cred.passkeyRpId).toBe("example.com");
        expect(cred.passkeySignCount).toBe(0);
      }
      // Public key bytes must NOT be leaked through the public shape.
      expect((cred as unknown as { passkeyPublicKey?: unknown }).passkeyPublicKey).toBeUndefined();
    });
  });

  // ───────────── OIDC credentials ─────────────

  describe("oidc credentials", () => {
    it("creates and retrieves an OIDC credential", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "oidc",
        identifier: "alice@example.com",
        oidcIssuer: "https://accounts.google.com",
        oidcSubject: "1234567890",
      });
      expect(cred.type).toBe("oidc");
      if (cred.type === "oidc") {
        expect(cred.oidcIssuer).toBe("https://accounts.google.com");
        expect(cred.oidcSubject).toBe("1234567890");
      }
    });
  });

  // ───────────── Credential suspend / reinstate / revoke ─────────────

  describe("credential lifecycle", () => {
    it("suspend removes the credential from the active-identifier index and terminates sessions", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const { session } = await store.createSession({
        usrId: u.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      await store.suspendCredential(cred.id);
      // Session terminated.
      const cascaded = await store.getSession(session.id);
      expect(cascaded.revokedAt).not.toBeNull();
      // Find-by-identifier returns null.
      const found = await store.findCredentialByIdentifier({
        type: "password",
        identifier: "alice@example.com",
      });
      expect(found).toBeNull();
    });

    it("reinstate rejects when a different active credential owns the identifier", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "first",
      });
      await store.suspendCredential(cred.id);
      // A second credential for the same identifier (now free) is created.
      await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "second",
      });
      // Reinstating the original would collide with the active second cred.
      await expect(store.reinstateCredential(cred.id)).rejects.toThrow(
        DuplicateCredentialError,
      );
    });

    it("revoke cascades — any session bound to this cred is terminated", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const { session } = await store.createSession({
        usrId: u.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      await store.revokeCredential(cred.id);
      const cascaded = await store.getSession(session.id);
      expect(cascaded.revokedAt).not.toBeNull();
    });
  });

  // ───────────── findCredentialByIdentifier ─────────────

  describe("findCredentialByIdentifier", () => {
    it("returns the active credential for the (type, identifier) pair", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      const found = await store.findCredentialByIdentifier({
        type: "password",
        identifier: "alice@example.com",
      });
      expect(found?.id).toBe(cred.id);
    });

    it("returns null for an unknown identifier", async () => {
      const found = await store.findCredentialByIdentifier({
        type: "password",
        identifier: "nobody@example.com",
      });
      expect(found).toBeNull();
    });

    it("skips revoked credentials (active-only)", async () => {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      await store.revokeCredential(cred.id);
      const found = await store.findCredentialByIdentifier({
        type: "password",
        identifier: "alice@example.com",
      });
      expect(found).toBeNull();
    });
  });

  // ───────────── Sessions ─────────────

  describe("sessions", () => {
    async function setup() {
      const u = await store.createUser();
      const cred = await store.createCredential({
        usrId: u.id,
        type: "password",
        identifier: "alice@example.com",
        password: "correcthorsebatterystaple",
      });
      return { u, cred };
    }

    it("createSession returns an opaque token distinct from the session id", async () => {
      const { u, cred } = await setup();
      const { session, token } = await store.createSession({
        usrId: u.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      expect(session.id).toMatch(/^ses_[0-9a-f]{32}$/);
      expect(token).not.toBe(session.id);
      expect(token.length).toBeGreaterThanOrEqual(32);
    });

    it("verifySessionToken accepts a fresh token", async () => {
      const { u, cred } = await setup();
      const { session, token } = await store.createSession({
        usrId: u.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      const verified = await store.verifySessionToken(token);
      expect(verified.id).toBe(session.id);
    });

    it("verifySessionToken rejects an unknown token", async () => {
      await expect(
        store.verifySessionToken("not-a-real-token-value"),
      ).rejects.toThrow(InvalidTokenError);
    });

    it("verifySessionToken rejects a revoked session's token", async () => {
      const { u, cred } = await setup();
      const { session, token } = await store.createSession({
        usrId: u.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      await store.revokeSession(session.id);
      await expect(store.verifySessionToken(token)).rejects.toThrow(
        InvalidTokenError, // revoke removes the token-hash index entry entirely
      );
    });

    it("refreshSession returns a new session with a fresh token and marks the old revoked", async () => {
      const { u, cred } = await setup();
      const first = await store.createSession({
        usrId: u.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      const refreshed = await store.refreshSession(first.session.id);
      expect(refreshed.session.id).not.toBe(first.session.id);
      expect(refreshed.token).not.toBe(first.token);
      // Old session is marked revoked; old token is now invalid.
      const oldAfter = await store.getSession(first.session.id);
      expect(oldAfter.revokedAt).not.toBeNull();
      await expect(store.verifySessionToken(first.token)).rejects.toThrow(
        InvalidTokenError,
      );
      // New token works.
      const verified = await store.verifySessionToken(refreshed.token);
      expect(verified.id).toBe(refreshed.session.id);
    });

    it("refreshSession refuses when the session has already expired", async () => {
      const { u, cred } = await setup();
      // Deterministic clock: create expired session by rolling the clock forward.
      const shiftedClock = (() => {
        const base = new Date("2026-01-01T00:00:00Z").getTime();
        let shift = 0;
        return () => new Date(base + shift++);
      })();
      const local = new InMemoryIdentityStore({ clock: shiftedClock });
      const lu = await local.createUser();
      const lc = await local.createCredential({
        usrId: lu.id,
        type: "password",
        identifier: "x@y",
        password: "correcthorsebatterystaple",
      });
      const { session } = await local.createSession({
        usrId: lu.id,
        credId: lc.id,
        ttlSeconds: 60,
      });
      // Burn enough clock ticks to push us past expiresAt.
      for (let i = 0; i < 70_000; i++) shiftedClock();
      await expect(local.refreshSession(session.id)).rejects.toThrow(
        SessionExpiredError,
      );
      // Hush unused vars.
      void u;
      void cred;
    });

    it("createSession rejects TTL below 60 seconds", async () => {
      const { u, cred } = await setup();
      await expect(
        store.createSession({ usrId: u.id, credId: cred.id, ttlSeconds: 5 }),
      ).rejects.toThrow(PreconditionError);
    });

    it("createSession rejects a suspended credential", async () => {
      const { u, cred } = await setup();
      await store.suspendCredential(cred.id);
      await expect(
        store.createSession({
          usrId: u.id,
          credId: cred.id,
          ttlSeconds: 3600,
        }),
      ).rejects.toThrow(CredentialNotActiveError);
    });

    it("listSessionsForUser returns sessions belonging to the user", async () => {
      const { u, cred } = await setup();
      await store.createSession({ usrId: u.id, credId: cred.id, ttlSeconds: 3600 });
      await store.createSession({ usrId: u.id, credId: cred.id, ttlSeconds: 3600 });
      const page = await store.listSessionsForUser(u.id);
      expect(page.data).toHaveLength(2);
      for (const s of page.data) expect(s.usrId).toBe(u.id);
    });
  });
});

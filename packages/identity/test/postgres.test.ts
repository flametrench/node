// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { generate } from "@flametrench/ids";

import {
  AlreadyTerminalError,
  CredentialNotActiveError,
  DuplicateCredentialError,
  InvalidCredentialError,
  InvalidTokenError,
  NotFoundError,
  PreconditionError,
  SessionExpiredError,
  generateRecoveryCode,
  totpCompute,
  type UsrId,
} from "../src/index.js";
import { PostgresIdentityStore } from "../src/postgres.js";

const POSTGRES_URL = process.env.IDENTITY_POSTGRES_URL;
const hasPostgres = Boolean(POSTGRES_URL);

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");

describe.skipIf(!hasPostgres)("PostgresIdentityStore", () => {
  let pool: Pool;
  let store: PostgresIdentityStore;

  beforeAll(async () => {
    pool = new Pool({ connectionString: POSTGRES_URL });
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
    await pool.query(SCHEMA_SQL);
    store = new PostgresIdentityStore(pool);
  });

  // ───── Users ─────

  it("createUser yields a fresh active usr_ id", async () => {
    const user = await store.createUser();
    expect(user.id).toMatch(/^usr_[0-9a-f]{32}$/);
    expect(user.status).toBe("active");
  });

  it("getUser raises NotFoundError for unknown ids", async () => {
    await expect(store.getUser(generate("usr") as UsrId)).rejects.toThrow(
      NotFoundError,
    );
  });

  it("suspend → reinstate round-trip", async () => {
    const user = await store.createUser();
    const suspended = await store.suspendUser(user.id);
    expect(suspended.status).toBe("suspended");
    const reinstated = await store.reinstateUser(user.id);
    expect(reinstated.status).toBe("active");
  });

  it("revokeUser cascades to credentials and sessions", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "correct horse battery staple",
    });
    const { session } = await store.createSession({
      usrId: user.id,
      credId: cred.id,
      ttlSeconds: 3600,
    });
    await store.revokeUser(user.id);
    const fetchedUser = await store.getUser(user.id);
    expect(fetchedUser.status).toBe("revoked");
    const fetchedCred = await store.getCredential(cred.id);
    expect(fetchedCred.status).toBe("revoked");
    const fetchedSes = await store.getSession(session.id);
    expect(fetchedSes.revokedAt).not.toBeNull();
  });

  it("double-revoke is rejected", async () => {
    const user = await store.createUser();
    await store.revokeUser(user.id);
    await expect(store.revokeUser(user.id)).rejects.toThrow(AlreadyTerminalError);
  });

  // ───── listUsers (ADR 0015) ─────

  it("listUsers returns all users in id ASC order", async () => {
    const a = await store.createUser();
    const b = await store.createUser();
    const c = await store.createUser();
    const page = await store.listUsers();
    expect(page.data.map((u) => u.id)).toEqual([a.id, b.id, c.id]);
    expect(page.nextCursor).toBeNull();
  });

  it("listUsers status filter excludes other states", async () => {
    const active = await store.createUser();
    const suspended = await store.createUser();
    await store.suspendUser(suspended.id);
    const page = await store.listUsers({ status: "active" });
    expect(page.data.map((u) => u.id)).toEqual([active.id]);
  });

  it("listUsers query is case-insensitive substring against active credential identifiers", async () => {
    const alice = await store.createUser();
    await store.createCredential({
      usrId: alice.id,
      type: "password",
      identifier: "alice@example.com",
      password: "long-enough-password",
    });
    const bob = await store.createUser();
    await store.createCredential({
      usrId: bob.id,
      type: "password",
      identifier: "bob@example.com",
      password: "long-enough-password",
    });
    const carol = await store.createUser();
    await store.createCredential({
      usrId: carol.id,
      type: "password",
      identifier: "carol@other.test",
      password: "long-enough-password",
    });
    const page = await store.listUsers({ query: "EXAMPLE" });
    expect(new Set(page.data.map((u) => u.id))).toEqual(new Set([alice.id, bob.id]));
  });

  it("listUsers query skips revoked credentials", async () => {
    const alice = await store.createUser();
    const cred = await store.createCredential({
      usrId: alice.id,
      type: "password",
      identifier: "gone@example.com",
      password: "long-enough-password",
    });
    await store.revokeCredential(cred.id);
    const page = await store.listUsers({ query: "gone@example.com" });
    expect(page.data).toEqual([]);
  });

  it("listUsers cursor walks pages", async () => {
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const u = await store.createUser();
      ids.push(u.id);
    }
    const page1 = await store.listUsers({ limit: 2 });
    expect(page1.data.map((u) => u.id)).toEqual([ids[0], ids[1]]);
    const page2 = await store.listUsers({ cursor: page1.nextCursor!, limit: 2 });
    expect(page2.data.map((u) => u.id)).toEqual([ids[2], ids[3]]);
    const page3 = await store.listUsers({ cursor: page2.nextCursor!, limit: 2 });
    expect(page3.data.map((u) => u.id)).toEqual([ids[4]]);
    expect(page3.nextCursor).toBeNull();
  });

  it("listUsers returns display_name on each row", async () => {
    const alice = await store.createUser({ displayName: "Alice" });
    const bob = await store.createUser();
    const page = await store.listUsers();
    const byId = new Map(page.data.map((u) => [u.id, u.displayName]));
    expect(byId.get(alice.id)).toBe("Alice");
    expect(byId.get(bob.id)).toBeNull();
  });

  // ───── display_name (ADR 0014) ─────

  it("createUser stores displayName when supplied; getUser round-trips it", async () => {
    const user = await store.createUser({ displayName: "Alice" });
    expect(user.displayName).toBe("Alice");
    const fetched = await store.getUser(user.id);
    expect(fetched.displayName).toBe("Alice");
  });

  it("createUser defaults displayName to null", async () => {
    const user = await store.createUser();
    expect(user.displayName).toBeNull();
  });

  it("updateUser sets, leaves untouched (omitted), and clears displayName", async () => {
    const user = await store.createUser({ displayName: "Original" });
    const renamed = await store.updateUser({ usrId: user.id, displayName: "Renamed" });
    expect(renamed.displayName).toBe("Renamed");
    const unchanged = await store.updateUser({ usrId: user.id });
    expect(unchanged.displayName).toBe("Renamed");
    const cleared = await store.updateUser({ usrId: user.id, displayName: null });
    expect(cleared.displayName).toBeNull();
  });

  it("updateUser allows renaming a suspended user", async () => {
    const user = await store.createUser({ displayName: "Before" });
    await store.suspendUser(user.id);
    const renamed = await store.updateUser({ usrId: user.id, displayName: "After" });
    expect(renamed.displayName).toBe("After");
    expect(renamed.status).toBe("suspended");
  });

  it("updateUser on a revoked user raises AlreadyTerminalError", async () => {
    const user = await store.createUser();
    await store.revokeUser(user.id);
    await expect(
      store.updateUser({ usrId: user.id, displayName: "Whatever" }),
    ).rejects.toThrow(AlreadyTerminalError);
  });

  it("updateUser on unknown user raises NotFoundError", async () => {
    await expect(
      store.updateUser({ usrId: generate("usr") as UsrId, displayName: "ghost" }),
    ).rejects.toThrow(NotFoundError);
  });

  it("displayName accepts full Unicode without normalization", async () => {
    const user = await store.createUser({ displayName: "山田 太郎" });
    expect((await store.getUser(user.id)).displayName).toBe("山田 太郎");
  });

  // ───── Credentials ─────

  it("creates a password credential and verifyPassword round-trips", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "correct horse battery staple",
    });
    expect(cred.type).toBe("password");
    const result = await store.verifyPassword({
      type: "password",
      identifier: "alice@example.com",
      password: "correct horse battery staple",
    });
    expect(result.usrId).toBe(user.id);
    expect(result.credId).toBe(cred.id);
  });

  it("verifyPassword rejects a wrong password", async () => {
    const user = await store.createUser();
    await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "correct horse battery staple",
    });
    await expect(
      store.verifyPassword({
        type: "password",
        identifier: "alice@example.com",
        password: "wrong",
      }),
    ).rejects.toThrow(InvalidCredentialError);
  });

  it("rejects a duplicate active credential on the same (type, identifier)", async () => {
    const user = await store.createUser();
    await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p1",
    });
    await expect(
      store.createCredential({
        usrId: user.id,
        type: "password",
        identifier: "alice@example.com",
        password: "p2",
      }),
    ).rejects.toThrow(DuplicateCredentialError);
  });

  it("rotateCredential revokes old, inserts new with replaces, terminates sessions", async () => {
    const user = await store.createUser();
    const oldCred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "old",
    });
    const { session } = await store.createSession({
      usrId: user.id,
      credId: oldCred.id,
      ttlSeconds: 3600,
    });
    const newCred = await store.rotateCredential({
      credId: oldCred.id,
      type: "password",
      newPassword: "new",
    });
    expect(newCred.replaces).toBe(oldCred.id);
    expect((await store.getCredential(oldCred.id)).status).toBe("revoked");
    expect((await store.getSession(session.id)).revokedAt).not.toBeNull();
    // Old password no longer verifies; new password does.
    await expect(
      store.verifyPassword({
        type: "password",
        identifier: "alice@example.com",
        password: "old",
      }),
    ).rejects.toThrow(InvalidCredentialError);
    const ok = await store.verifyPassword({
      type: "password",
      identifier: "alice@example.com",
      password: "new",
    });
    expect(ok.credId).toBe(newCred.id);
  });

  it("findCredentialByIdentifier returns active only", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p",
    });
    const found = await store.findCredentialByIdentifier({
      type: "password",
      identifier: "alice@example.com",
    });
    expect(found?.id).toBe(cred.id);

    await store.revokeCredential(cred.id);
    const found2 = await store.findCredentialByIdentifier({
      type: "password",
      identifier: "alice@example.com",
    });
    expect(found2).toBeNull();
  });

  it("suspend → reinstate credential preserves the row through state transitions", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p",
    });
    await store.suspendCredential(cred.id);
    expect((await store.getCredential(cred.id)).status).toBe("suspended");
    await store.reinstateCredential(cred.id);
    expect((await store.getCredential(cred.id)).status).toBe("active");
  });

  // ───── Sessions ─────

  it("createSession returns a token distinct from the session id and verifies", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p",
    });
    const { session, token } = await store.createSession({
      usrId: user.id,
      credId: cred.id,
      ttlSeconds: 3600,
    });
    expect(token).not.toBe(session.id);
    const verified = await store.verifySessionToken(token);
    expect(verified.id).toBe(session.id);
  });

  it("verifySessionToken rejects an unknown token", async () => {
    await expect(store.verifySessionToken("nope")).rejects.toThrow(InvalidTokenError);
  });

  it("verifySessionToken rejects a revoked session's token", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p",
    });
    const { session, token } = await store.createSession({
      usrId: user.id,
      credId: cred.id,
      ttlSeconds: 3600,
    });
    await store.revokeSession(session.id);
    await expect(store.verifySessionToken(token)).rejects.toThrow(SessionExpiredError);
  });

  it("refreshSession returns a new session with a fresh token", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p",
    });
    const { session, token } = await store.createSession({
      usrId: user.id,
      credId: cred.id,
      ttlSeconds: 3600,
    });
    const refreshed = await store.refreshSession(session.id);
    expect(refreshed.session.id).not.toBe(session.id);
    expect(refreshed.token).not.toBe(token);
    expect((await store.getSession(session.id)).revokedAt).not.toBeNull();
  });

  it("createSession rejects TTL below 60 seconds", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p",
    });
    await expect(
      store.createSession({ usrId: user.id, credId: cred.id, ttlSeconds: 30 }),
    ).rejects.toThrow(PreconditionError);
  });

  it("createSession rejects a suspended credential", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p",
    });
    await store.suspendCredential(cred.id);
    await expect(
      store.createSession({ usrId: user.id, credId: cred.id, ttlSeconds: 3600 }),
    ).rejects.toThrow(CredentialNotActiveError);
  });

  it("listSessionsForUser returns sessions belonging to the user", async () => {
    const user = await store.createUser();
    const cred = await store.createCredential({
      usrId: user.id,
      type: "password",
      identifier: "alice@example.com",
      password: "p",
    });
    await store.createSession({ usrId: user.id, credId: cred.id, ttlSeconds: 3600 });
    await store.createSession({ usrId: user.id, credId: cred.id, ttlSeconds: 3600 });
    const page = await store.listSessionsForUser(user.id);
    expect(page.data).toHaveLength(2);
  });

  // ───── MFA ─────

  it("enrollTotpFactor → confirmTotpFactor → verifyMfa round-trips", async () => {
    const user = await store.createUser();
    const enroll = await store.enrollTotpFactor(user.id, "iPhone");
    expect(enroll.factor.status).toBe("pending");
    expect(enroll.secretB32.length).toBeGreaterThan(0);
    expect(enroll.otpauthUri.startsWith("otpauth://totp/")).toBe(true);

    // Compute a valid code from the otpauth URI's secret.
    const secretB32 = enroll.secretB32;
    const secretBytes = base32Decode(secretB32);
    const code = totpCompute(secretBytes, Math.floor(Date.now() / 1000));

    const active = await store.confirmTotpFactor(enroll.factor.id, code);
    expect(active.status).toBe("active");

    const result = await store.verifyMfa(user.id, { type: "totp", code });
    expect(result.type).toBe("totp");
    expect(result.mfaId).toBe(active.id);
  });

  it("enforces at-most-one active TOTP factor per user", async () => {
    const user = await store.createUser();
    const first = await store.enrollTotpFactor(user.id, "iPhone");
    const code = totpCompute(
      base32Decode(first.secretB32),
      Math.floor(Date.now() / 1000),
    );
    await store.confirmTotpFactor(first.factor.id, code);
    await expect(store.enrollTotpFactor(user.id, "Yubico")).rejects.toThrow(
      PreconditionError,
    );
  });

  it("recovery codes verify once and then are consumed", async () => {
    const user = await store.createUser();
    const enroll = await store.enrollRecoveryFactor(user.id);
    expect(enroll.codes).toHaveLength(10);
    const first = enroll.codes[0]!;
    const result = await store.verifyMfa(user.id, { type: "recovery", code: first });
    expect(result.type).toBe("recovery");
    // Using the same code again fails.
    await expect(
      store.verifyMfa(user.id, { type: "recovery", code: first }),
    ).rejects.toThrow(InvalidCredentialError);
    // Remaining count drops.
    const factors = await store.listMfaFactors(user.id);
    const recovery = factors.find((f) => f.type === "recovery");
    expect(recovery && recovery.type === "recovery" && recovery.remaining).toBe(9);
  });

  it("recovery factor rejects malformed input", async () => {
    const user = await store.createUser();
    await store.enrollRecoveryFactor(user.id);
    await expect(
      store.verifyMfa(user.id, { type: "recovery", code: "not-a-code" }),
    ).rejects.toThrow(InvalidCredentialError);
  });

  it("recovery factor rejects an unknown but well-formed code", async () => {
    const user = await store.createUser();
    await store.enrollRecoveryFactor(user.id);
    // Generate a random 12-char recovery code that almost certainly won't match.
    let bogus = generateRecoveryCode();
    // 1-in-31^12 collision; treat as zero for test purposes.
    await expect(
      store.verifyMfa(user.id, { type: "recovery", code: bogus }),
    ).rejects.toThrow(InvalidCredentialError);
  });

  it("revokeMfaFactor frees up the singleton slot", async () => {
    const user = await store.createUser();
    const first = await store.enrollTotpFactor(user.id, "iPhone");
    const code = totpCompute(
      base32Decode(first.secretB32),
      Math.floor(Date.now() / 1000),
    );
    await store.confirmTotpFactor(first.factor.id, code);
    await store.revokeMfaFactor(first.factor.id);
    // Now enrolling a fresh TOTP should succeed.
    const second = await store.enrollTotpFactor(user.id, "Yubico");
    expect(second.factor.status).toBe("pending");
  });

  it("setMfaPolicy upserts and getMfaPolicy round-trips", async () => {
    const user = await store.createUser();
    expect(await store.getMfaPolicy(user.id)).toBeNull();
    const grace = new Date(Date.now() + 14 * 24 * 3600 * 1000);
    const set1 = await store.setMfaPolicy({
      usrId: user.id,
      required: true,
      graceUntil: grace,
    });
    expect(set1.required).toBe(true);
    expect(set1.graceUntil?.getTime()).toBeCloseTo(grace.getTime(), -3);
    const fetched = await store.getMfaPolicy(user.id);
    expect(fetched?.required).toBe(true);
    // Upsert: clear grace.
    const set2 = await store.setMfaPolicy({ usrId: user.id, required: true });
    expect(set2.graceUntil).toBeNull();
  });

  it("getMfaPolicy throws NotFoundError for unknown user", async () => {
    await expect(store.getMfaPolicy(generate("usr") as UsrId)).rejects.toThrow(
      NotFoundError,
    );
  });

  // ───── Outer-transaction nesting (ADR 0013) ─────

  it("createUser cooperates with an outer transaction (no nested-BEGIN error)", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresIdentityStore(client);
      const user = await nested.createUser({ displayName: "Nested" });
      // Outside-the-txn store cannot see the row yet.
      await expect(store.getUser(user.id)).rejects.toThrow(NotFoundError);
      await client.query("COMMIT");
      const fetched = await store.getUser(user.id);
      expect(fetched.displayName).toBe("Nested");
    } finally {
      client.release();
    }
  });

  it("rolling back an outer transaction undoes the inner createUser + createCredential", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresIdentityStore(client);
      const user = await nested.createUser();
      await nested.createCredential({
        usrId: user.id,
        type: "password",
        identifier: "rolled-back@example.test",
        password: "hunter22-long-enough",
      });
      await client.query("ROLLBACK");
      await expect(store.getUser(user.id)).rejects.toThrow(NotFoundError);
    } finally {
      client.release();
    }
  });

  it("outer transaction can commit a second SDK call after the first one rolls back its savepoint", async () => {
    // Seed a credential in the outside store so the nested duplicate fails.
    const seed = await store.createUser();
    await store.createCredential({
      usrId: seed.id,
      type: "password",
      identifier: "taken@example.test",
      password: "hunter22-long-enough",
    });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresIdentityStore(client);
      const user = await nested.createUser();
      await expect(
        nested.createCredential({
          usrId: user.id,
          type: "password",
          identifier: "taken@example.test",
          password: "hunter22-long-enough",
        }),
      ).rejects.toThrow(DuplicateCredentialError);
      // Outer txn is still usable — savepoint rolled back the failure.
      const cred = await nested.createCredential({
        usrId: user.id,
        type: "password",
        identifier: "survivor@example.test",
        password: "hunter22-long-enough",
      });
      await client.query("COMMIT");
      expect(cred.identifier).toBe("survivor@example.test");
      expect((await store.getUser(user.id)).id).toBe(user.id);
    } finally {
      client.release();
    }
  });

  it("multiple SDK calls in one outer transaction commit-or-rollback together", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresIdentityStore(client);
      const a = await nested.createUser();
      const b = await nested.createUser();
      await client.query("ROLLBACK");
      await expect(store.getUser(a.id)).rejects.toThrow(NotFoundError);
      await expect(store.getUser(b.id)).rejects.toThrow(NotFoundError);
    } finally {
      client.release();
    }
  });
});

if (!hasPostgres) {
  // eslint-disable-next-line no-console
  console.log(
    "[postgres.test.ts] IDENTITY_POSTGRES_URL not set; PostgresIdentityStore tests are skipped.\n" +
      "  Set e.g. `IDENTITY_POSTGRES_URL=postgresql://postgres:test@localhost:5432/flametrench_test` " +
      "with a reachable Postgres 16+ instance to run them.",
  );
}

/** RFC 4648 base32 decode (assumes upper-case input, ignores padding). */
function base32Decode(s: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const stripped = s.replace(/=+$/, "").toUpperCase();
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of stripped) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 char ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

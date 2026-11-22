// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// User-status gates, TOTP replay protection (ADR 0008, design 3A) and
// recovery re-enrollment, including "a refused operation changes nothing".
// Runs against InMemoryIdentityStore and, when IDENTITY_POSTGRES_URL is set,
// PostgresIdentityStore.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  InMemoryIdentityStore,
  InvalidCredentialError,
  InvalidPatTokenError,
  InvalidTokenError,
  PatRevokedError,
  PreconditionError,
  ReplayedTotpError,
  totpCompute,
  type IdentityStore,
} from "../src/index.js";
import { PostgresIdentityStore } from "../src/postgres.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");
const POSTGRES_URL = process.env.IDENTITY_POSTGRES_URL;

function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of input.replace(/=+$/, "").toUpperCase()) {
    value = (value << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

type MakeStore = (clock: () => Date) => Promise<IdentityStore>;

const PASSWORD = "long-enough-password-for-floor";
const T0 = new Date("2026-01-01T00:00:00Z");

function suite(name: string, makeStore: MakeStore): void {
  async function totpUser() {
    const clock = { now: T0 };
    const store = await makeStore(() => clock.now);
    const user = await store.createUser({});
    const enroll = await store.enrollTotpFactor(user.id, "phone");
    const secret = base32Decode(enroll.secretB32);
    const codeAt = (d: Date) => totpCompute(secret, Math.floor(d.getTime() / 1000));
    await store.confirmTotpFactor(enroll.factor.id, codeAt(T0));
    const at = (iso: string) => {
      clock.now = new Date(iso);
      return codeAt(clock.now);
    };
    return { store, user, clock, codeAt, at };
  }

  describe(`${name}: TOTP replay (design 3A)`, () => {
    it("rejects a never-used code from an older step once a newer step was accepted", async () => {
      const { store, user, codeAt, at } = await totpUser();
      const codeN = codeAt(new Date("2026-01-01T00:01:00Z"));
      const codeN1 = at("2026-01-01T00:01:30Z");
      await store.verifyMfa(user.id, { type: "totp", code: codeN1 });
      await expect(
        store.verifyMfa(user.id, { type: "totp", code: codeN }),
      ).rejects.toBeInstanceOf(ReplayedTotpError);
    });

    it("a refused replay does not advance or lock the factor", async () => {
      const { store, user, at } = await totpUser();
      const code = at("2026-01-01T00:01:00Z");
      await store.verifyMfa(user.id, { type: "totp", code });
      await expect(
        store.verifyMfa(user.id, { type: "totp", code }),
      ).rejects.toBeInstanceOf(ReplayedTotpError);
      const replay = await store.verifyMfa(user.id, { type: "totp", code }).catch((e: unknown) => e);
      expect(replay).toBeInstanceOf(InvalidCredentialError);
      expect((replay as ReplayedTotpError).code).toBe("unauthorized.totp_replayed");
      const next = at("2026-01-01T00:01:30Z");
      const ok = await store.verifyMfa(user.id, { type: "totp", code: next });
      expect(ok.type).toBe("totp");
    });

    it("a wrong code is InvalidCredentialError, not a replay, and consumes nothing", async () => {
      const { store, user, at } = await totpUser();
      const code = at("2026-01-01T00:01:00Z");
      const wrong = code === "000000" ? "111111" : "000000";
      await expect(
        store.verifyMfa(user.id, { type: "totp", code: wrong }),
      ).rejects.toBeInstanceOf(InvalidCredentialError);
      expect((await store.verifyMfa(user.id, { type: "totp", code })).type).toBe("totp");
    });

    it("concurrent verifies of one code: exactly one succeeds", async () => {
      const { store, user, at } = await totpUser();
      const code = at("2026-01-01T00:01:00Z");
      const results = await Promise.allSettled(
        Array.from({ length: 5 }, () => store.verifyMfa(user.id, { type: "totp", code })),
      );
      const ok = results.filter((r) => r.status === "fulfilled");
      const replayed = results.filter(
        (r) => r.status === "rejected" && r.reason instanceof ReplayedTotpError,
      );
      expect(ok.length).toBe(1);
      expect(replayed.length).toBe(4);
    });
  });

  describe(`${name}: user status gates`, () => {
    async function passwordUser() {
      const store = await makeStore(() => new Date());
      const user = await store.createUser({});
      await store.createCredential({
        type: "password",
        usrId: user.id,
        identifier: "u@example.com",
        password: PASSWORD,
      });
      return { store, user };
    }

    async function sessionUser() {
      const store = await makeStore(() => new Date());
      const user = await store.createUser({});
      const cred = await store.createCredential({
        type: "password",
        usrId: user.id,
        identifier: "s@example.com",
        password: PASSWORD,
      });
      const { session, token } = await store.createSession({
        usrId: user.id,
        credId: cred.id,
        ttlSeconds: 3600,
      });
      return { store, user, session, token };
    }

    it("after suspendUser, refreshSession is refused with precondition.user_not_active", async () => {
      const { store, user, session } = await sessionUser();
      await store.suspendUser(user.id);
      const err = await store.refreshSession(session.id).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(PreconditionError);
      expect((err as PreconditionError).code).toBe("precondition.user_not_active");
    });

    it("after suspendUser, verifySessionToken is refused with InvalidTokenError", async () => {
      const { store, user, token } = await sessionUser();
      await store.suspendUser(user.id);
      await expect(store.verifySessionToken(token)).rejects.toBeInstanceOf(InvalidTokenError);
    });

    it("an active user's session still verifies and refreshes", async () => {
      const { store, session, token } = await sessionUser();
      expect((await store.verifySessionToken(token)).id).toBe(session.id);
      const fresh = await store.refreshSession(session.id);
      expect((await store.verifySessionToken(fresh.token)).id).toBe(fresh.session.id);
    });

    it("a suspended user gets the same InvalidCredentialError for right and wrong passwords", async () => {
      const { store, user } = await passwordUser();
      await store.suspendUser(user.id);
      for (const password of [PASSWORD, "wrong-password-but-long-enough"]) {
        const err = await store
          .verifyPassword({ type: "password", identifier: "u@example.com", password })
          .catch((e: unknown) => e);
        expect(err).toBeInstanceOf(InvalidCredentialError);
        expect((err as Error).message).toBe("Invalid credential");
      }
    });

    it("a refused PAT verify for a suspended owner does not revoke the PAT", async () => {
      const store = await makeStore(() => new Date());
      const user = await store.createUser({});
      const { pat, token } = await store.createPat({ usrId: user.id, name: "ci", scope: [] });
      await store.suspendUser(user.id);
      await expect(store.verifyPatToken(token)).rejects.toBeInstanceOf(InvalidPatTokenError);
      const after = await store.getPat(pat.id);
      expect(after.revokedAt).toBeNull();
      expect(after.lastUsedAt).toBeNull();
    });

    it("revokeUser alone revokes the user's PATs", async () => {
      const store = await makeStore(() => new Date());
      const user = await store.createUser({});
      const { pat, token } = await store.createPat({ usrId: user.id, name: "ci", scope: [] });
      await store.revokeUser(user.id);
      expect((await store.getPat(pat.id)).revokedAt).not.toBeNull();
      await expect(store.verifyPatToken(token)).rejects.toBeInstanceOf(PatRevokedError);
    });

    it("revokeUser's PAT cascade succeeds when the app clock lags the PAT's created_at", async () => {
      // Postgres stamps pat.created_at with the DB clock and revoked_at with the
      // app clock; CHECK (revoked_at >= created_at) must not roll back the revoke.
      const store = await makeStore(() => new Date("2000-01-01T00:00:00Z"));
      const user = await store.createUser({});
      const { pat } = await store.createPat({ usrId: user.id, name: "ci", scope: [] });
      const before = await store.getPat(pat.id);
      await store.revokeUser(user.id);
      const after = await store.getPat(pat.id);
      expect(after.revokedAt).not.toBeNull();
      expect(after.revokedAt!.getTime()).toBeGreaterThanOrEqual(before.createdAt.getTime());
      expect((await store.getUser(user.id)).status).toBe("revoked");
    });

    it("a refused createPat for a revoked user creates no PAT", async () => {
      const store = await makeStore(() => new Date());
      const user = await store.createUser({});
      await store.revokeUser(user.id);
      await expect(
        store.createPat({ usrId: user.id, name: "ci", scope: [] }),
      ).rejects.toBeInstanceOf(PreconditionError);
      expect((await store.listPatsForUser(user.id)).data).toHaveLength(0);
    });

    for (const status of ["suspended", "revoked"] as const) {
      it(`createPat for a ${status} user is refused with precondition.user_not_active`, async () => {
        const store = await makeStore(() => new Date());
        const user = await store.createUser({});
        if (status === "suspended") await store.suspendUser(user.id);
        else await store.revokeUser(user.id);
        const err = await store
          .createPat({ usrId: user.id, name: "ci", scope: [] })
          .catch((e: unknown) => e);
        expect(err).toBeInstanceOf(PreconditionError);
        expect((err as PreconditionError).code).toBe("precondition.user_not_active");
        expect(await store.listPatsForUser(user.id)).toEqual({ data: [], nextCursor: null });
      });
    }

    it("a suspended user's valid recovery code is refused and stays unconsumed", async () => {
      const store = await makeStore(() => new Date());
      const user = await store.createUser({});
      const { codes } = await store.enrollRecoveryFactor(user.id);
      await store.suspendUser(user.id);
      await expect(
        store.verifyMfa(user.id, { type: "recovery", code: codes[0]! }),
      ).rejects.toBeInstanceOf(InvalidCredentialError);
      await store.reinstateUser(user.id);
      const ok = await store.verifyMfa(user.id, { type: "recovery", code: codes[0]! });
      expect(ok.type).toBe("recovery");
    });

    it("a suspended user's valid TOTP code is refused and its step is not consumed", async () => {
      const { store, user, at } = await totpUser();
      const code = at("2026-01-01T00:01:00Z");
      await store.suspendUser(user.id);
      await expect(
        store.verifyMfa(user.id, { type: "totp", code }),
      ).rejects.toBeInstanceOf(InvalidCredentialError);
      await store.reinstateUser(user.id);
      const ok = await store.verifyMfa(user.id, { type: "totp", code });
      expect(ok.type).toBe("totp");
    });
  });

  describe(`${name}: recovery re-enrollment`, () => {
    it("a refused re-enroll over an unexhausted set changes nothing", async () => {
      const store = await makeStore(() => new Date());
      const user = await store.createUser({});
      const first = await store.enrollRecoveryFactor(user.id);
      await store.verifyMfa(user.id, { type: "recovery", code: first.codes[0]! });
      await expect(store.enrollRecoveryFactor(user.id)).rejects.toBeInstanceOf(PreconditionError);
      const factors = await store.listMfaFactors(user.id);
      expect(factors.filter((f) => f.type === "recovery")).toHaveLength(1);
      expect((await store.getMfaFactor(first.factor.id)).status).toBe("active");
      const ok = await store.verifyMfa(user.id, { type: "recovery", code: first.codes[1]! });
      expect(ok.mfaId).toBe(first.factor.id);
    });

    it("the revoked exhausted set's codes are not honoured by the replacement", async () => {
      const store = await makeStore(() => new Date());
      const user = await store.createUser({});
      const first = await store.enrollRecoveryFactor(user.id);
      for (const code of first.codes) {
        await store.verifyMfa(user.id, { type: "recovery", code });
      }
      await store.enrollRecoveryFactor(user.id);
      await expect(
        store.verifyMfa(user.id, { type: "recovery", code: first.codes[0]! }),
      ).rejects.toBeInstanceOf(InvalidCredentialError);
    });
  });
}

suite("in-memory", async (clock) => new InMemoryIdentityStore({ clock }));

describe.skipIf(!POSTGRES_URL)("postgres", () => {
  let pool: Pool;
  beforeAll(() => {
    pool = new Pool({ connectionString: POSTGRES_URL });
  });
  afterAll(async () => {
    await pool.end();
  });
  suite("postgres", async (clock) => {
    await pool.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
    await pool.query(SCHEMA_SQL);
    return new PostgresIdentityStore(pool, { clock });
  });
});

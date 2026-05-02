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
  InMemoryIdentityStore,
  InvalidPatTokenError,
  NotFoundError,
  PatExpiredError,
  PatRevokedError,
  PreconditionError,
  type PatId,
} from "../src/index.js";
import { PostgresIdentityStore } from "../src/postgres.js";

const POSTGRES_URL = process.env.IDENTITY_POSTGRES_URL;
const hasPostgres = Boolean(POSTGRES_URL);

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");

describe("InMemoryIdentityStore — personal access tokens (ADR 0016)", () => {
  // Controllable clock for deterministic last_used_at coalescing tests.
  let now = new Date("2026-05-01T12:00:00Z");
  let store: InMemoryIdentityStore;

  beforeEach(() => {
    now = new Date("2026-05-01T12:00:00Z");
    // coalesce=0 in default test store so every verify writes back; the
    // coalescing tests below construct their own with a 60s window.
    store = new InMemoryIdentityStore({
      clock: () => now,
      patLastUsedCoalesceSeconds: 0,
    });
  });

  describe("createPat", () => {
    it("returns a wire-format token and a PersonalAccessToken record", async () => {
      const u = await store.createUser();
      const r = await store.createPat({
        usrId: u.id,
        name: "laptop-cli",
        scope: ["repo:read"],
      });
      expect(r.pat.id).toMatch(/^pat_[0-9a-f]{32}$/);
      expect(r.pat.name).toBe("laptop-cli");
      expect(r.pat.scope).toEqual(["repo:read"]);
      expect(r.pat.status).toBe("active");
      expect(r.pat.lastUsedAt).toBeNull();
      expect(r.pat.expiresAt).toBeNull();
      expect(r.token).toMatch(/^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$/);
      // The id segment in the token must match the row's id.
      expect(r.token.slice(4, 36)).toBe(r.pat.id.slice(4));
    });

    it("rejects empty name", async () => {
      const u = await store.createUser();
      await expect(
        store.createPat({ usrId: u.id, name: "", scope: [] }),
      ).rejects.toThrow(PreconditionError);
    });

    it("rejects name longer than 120 chars", async () => {
      const u = await store.createUser();
      await expect(
        store.createPat({ usrId: u.id, name: "x".repeat(121), scope: [] }),
      ).rejects.toThrow(PreconditionError);
    });

    it("rejects expires_at in the past", async () => {
      const u = await store.createUser();
      await expect(
        store.createPat({
          usrId: u.id,
          name: "cli",
          scope: [],
          expiresAt: new Date("2026-04-01T00:00:00Z"),
        }),
      ).rejects.toThrow(PreconditionError);
    });

    // security-audit-v0.3.md H1: ADR 0016 §"Constraints" caps expires_at
    // at 365 days from creation. Pre-fix this was unenforced.
    it("accepts expires_at exactly 365 days out (cap inclusive)", async () => {
      const u = await store.createUser();
      const exp = new Date(now.getTime() + 365 * 86400 * 1000);
      const r = await store.createPat({
        usrId: u.id,
        name: "cli",
        scope: [],
        expiresAt: exp,
      });
      expect(r.pat.expiresAt?.toISOString()).toBe(exp.toISOString());
    });

    it("rejects expires_at beyond the 365-day cap", async () => {
      const u = await store.createUser();
      const exp = new Date(now.getTime() + 365 * 86400 * 1000 + 1000); // +1 second past cap
      await expect(
        store.createPat({ usrId: u.id, name: "cli", scope: [], expiresAt: exp }),
      ).rejects.toThrow(PreconditionError);
    });

    it("refuses to issue PATs for revoked users", async () => {
      const u = await store.createUser();
      await store.revokeUser(u.id);
      await expect(
        store.createPat({ usrId: u.id, name: "cli", scope: [] }),
      ).rejects.toThrow(AlreadyTerminalError);
    });
  });

  describe("verifyPatToken — happy path", () => {
    it("returns VerifiedPat with usr_id and scope", async () => {
      const u = await store.createUser();
      const r = await store.createPat({
        usrId: u.id,
        name: "cli",
        scope: ["admin"],
      });
      const verified = await store.verifyPatToken(r.token);
      expect(verified.patId).toBe(r.pat.id);
      expect(verified.usrId).toBe(u.id);
      expect(verified.scope).toEqual(["admin"]);
    });

    it("updates lastUsedAt on first verify (coalesce=0)", async () => {
      const u = await store.createUser();
      const r = await store.createPat({ usrId: u.id, name: "cli", scope: [] });
      expect(r.pat.lastUsedAt).toBeNull();

      now = new Date(now.getTime() + 5_000);
      await store.verifyPatToken(r.token);
      const reread = await store.getPat(r.pat.id);
      expect(reread.lastUsedAt?.toISOString()).toBe(now.toISOString());
    });
  });

  describe("verifyPatToken — error ordering", () => {
    it("throws InvalidPatTokenError for malformed bearer", async () => {
      await expect(store.verifyPatToken("not-a-pat")).rejects.toThrow(
        InvalidPatTokenError,
      );
    });

    it("throws InvalidPatTokenError for non-pat prefix", async () => {
      await expect(
        store.verifyPatToken(
          `shr_${"a".repeat(32)}_secretvalue`,
        ),
      ).rejects.toThrow(InvalidPatTokenError);
    });

    it("throws InvalidPatTokenError for missing row (timing oracle defense)", async () => {
      await expect(
        store.verifyPatToken(`pat_${"a".repeat(32)}_anysecret`),
      ).rejects.toThrow(InvalidPatTokenError);
    });

    it("throws InvalidPatTokenError for wrong secret (same shape)", async () => {
      const u = await store.createUser();
      const r = await store.createPat({ usrId: u.id, name: "cli", scope: [] });
      const idHex = r.pat.id.slice(4);
      await expect(
        store.verifyPatToken(`pat_${idHex}_wrongSecret`),
      ).rejects.toThrow(InvalidPatTokenError);
    });

    it("throws PatRevokedError before expiry/secret checks", async () => {
      const u = await store.createUser();
      const r = await store.createPat({
        usrId: u.id,
        name: "cli",
        scope: [],
        expiresAt: new Date("2026-06-01T00:00:00Z"),
      });
      await store.revokePat(r.pat.id);
      await expect(store.verifyPatToken(r.token)).rejects.toThrow(
        PatRevokedError,
      );
    });

    it("throws PatExpiredError after expires_at", async () => {
      const u = await store.createUser();
      const r = await store.createPat({
        usrId: u.id,
        name: "cli",
        scope: [],
        expiresAt: new Date("2026-05-01T13:00:00Z"),
      });
      now = new Date("2026-05-02T00:00:00Z");
      await expect(store.verifyPatToken(r.token)).rejects.toThrow(
        PatExpiredError,
      );
    });
  });

  describe("revokePat", () => {
    it("marks the row revoked", async () => {
      const u = await store.createUser();
      const r = await store.createPat({ usrId: u.id, name: "cli", scope: [] });
      const revoked = await store.revokePat(r.pat.id);
      expect(revoked.status).toBe("revoked");
      expect(revoked.revokedAt?.toISOString()).toBe(now.toISOString());
    });

    it("is idempotent", async () => {
      const u = await store.createUser();
      const r = await store.createPat({ usrId: u.id, name: "cli", scope: [] });
      const first = await store.revokePat(r.pat.id);
      now = new Date(now.getTime() + 3_600_000);
      const second = await store.revokePat(r.pat.id);
      expect(second.revokedAt?.toISOString()).toBe(first.revokedAt?.toISOString());
    });

    it("throws NotFoundError for unknown patId", async () => {
      await expect(store.revokePat(generate("pat") as PatId)).rejects.toThrow(
        NotFoundError,
      );
    });
  });

  describe("listPatsForUser", () => {
    it("returns id-ordered PATs scoped to the user", async () => {
      const alice = await store.createUser();
      const bob = await store.createUser();
      const a1 = await store.createPat({
        usrId: alice.id,
        name: "a-1",
        scope: [],
      });
      await new Promise((r) => setTimeout(r, 2));
      const a2 = await store.createPat({
        usrId: alice.id,
        name: "a-2",
        scope: [],
      });
      await store.createPat({ usrId: bob.id, name: "bob-1", scope: [] });

      const page = await store.listPatsForUser(alice.id);
      expect(page.data.length).toBe(2);
      expect(page.data[0]!.id).toBe(a1.pat.id);
      expect(page.data[1]!.id).toBe(a2.pat.id);
      expect(page.nextCursor).toBeNull();
    });

    it("filters by status", async () => {
      const u = await store.createUser();
      const live = await store.createPat({
        usrId: u.id,
        name: "live",
        scope: [],
      });
      const rev = await store.createPat({ usrId: u.id, name: "rev", scope: [] });
      await store.revokePat(rev.pat.id);

      const activeOnly = await store.listPatsForUser(u.id, { status: "active" });
      expect(activeOnly.data.length).toBe(1);
      expect(activeOnly.data[0]!.id).toBe(live.pat.id);

      const revokedOnly = await store.listPatsForUser(u.id, {
        status: "revoked",
      });
      expect(revokedOnly.data.length).toBe(1);
      expect(revokedOnly.data[0]!.id).toBe(rev.pat.id);
    });

    it("paginates with cursor", async () => {
      const u = await store.createUser();
      const ids: PatId[] = [];
      for (let i = 0; i < 5; i++) {
        await new Promise((r) => setTimeout(r, 2));
        const created = await store.createPat({
          usrId: u.id,
          name: `p${i}`,
          scope: [],
        });
        ids.push(created.pat.id);
      }
      ids.sort();

      const first = await store.listPatsForUser(u.id, { limit: 2 });
      expect(first.data.length).toBe(2);
      expect(first.nextCursor).not.toBeNull();
      const second = await store.listPatsForUser(u.id, {
        cursor: first.nextCursor!,
        limit: 2,
      });
      expect(second.data.length).toBe(2);
      expect(second.data[0]!.id).toBe(ids[2]);
    });
  });

  describe("lastUsedAt coalescing (ADR 0016 §'Operational notes')", () => {
    it("does NOT update within the coalescing window", async () => {
      now = new Date("2026-05-01T12:00:00Z");
      const coalesceStore = new InMemoryIdentityStore({
        clock: () => now,
        patLastUsedCoalesceSeconds: 60,
      });
      const u = await coalesceStore.createUser();
      const r = await coalesceStore.createPat({
        usrId: u.id,
        name: "cli",
        scope: [],
      });

      now = new Date(now.getTime() + 5_000);
      await coalesceStore.verifyPatToken(r.token);
      const after1 = (await coalesceStore.getPat(r.pat.id)).lastUsedAt;

      now = new Date(now.getTime() + 10_000); // 15s in — within 60s window
      await coalesceStore.verifyPatToken(r.token);
      const after2 = (await coalesceStore.getPat(r.pat.id)).lastUsedAt;

      expect(after2?.toISOString()).toBe(after1?.toISOString());
    });

    it("updates after the coalescing window expires", async () => {
      now = new Date("2026-05-01T12:00:00Z");
      const coalesceStore = new InMemoryIdentityStore({
        clock: () => now,
        patLastUsedCoalesceSeconds: 60,
      });
      const u = await coalesceStore.createUser();
      const r = await coalesceStore.createPat({
        usrId: u.id,
        name: "cli",
        scope: [],
      });

      now = new Date(now.getTime() + 5_000);
      await coalesceStore.verifyPatToken(r.token);
      const after1 = (await coalesceStore.getPat(r.pat.id)).lastUsedAt;

      now = new Date(now.getTime() + 90_000); // 95s past first verify — past window
      await coalesceStore.verifyPatToken(r.token);
      const after2 = (await coalesceStore.getPat(r.pat.id)).lastUsedAt;

      expect(after2?.toISOString()).not.toBe(after1?.toISOString());
      expect(after2?.toISOString()).toBe(now.toISOString());
    });
  });
});

describe.skipIf(!hasPostgres)(
  "PostgresIdentityStore — personal access tokens (ADR 0016)",
  () => {
    let pool: Pool;
    let now = new Date("2026-05-01T12:00:00Z");
    let store: PostgresIdentityStore;

    beforeAll(async () => {
      pool = new Pool({ connectionString: POSTGRES_URL });
    });

    afterAll(async () => {
      await pool.end();
    });

    beforeEach(async () => {
      await pool.query(
        `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`,
      );
      await pool.query(SCHEMA_SQL);
      now = new Date("2026-05-01T12:00:00Z");
      store = new PostgresIdentityStore(pool, {
        clock: () => now,
        patLastUsedCoalesceSeconds: 0,
      });
    });

    it("createPat persists a row and returns wire-format token", async () => {
      const u = await store.createUser();
      const r = await store.createPat({
        usrId: u.id,
        name: "laptop-cli",
        scope: ["repo:read"],
      });
      expect(r.pat.id).toMatch(/^pat_[0-9a-f]{32}$/);
      expect(r.pat.name).toBe("laptop-cli");
      expect(r.pat.scope).toEqual(["repo:read"]);
      expect(r.pat.status).toBe("active");
      expect(r.token).toMatch(/^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$/);
      expect(r.token.slice(4, 36)).toBe(r.pat.id.slice(4));
    });

    it("verifyPatToken returns VerifiedPat with usr_id and scope", async () => {
      const u = await store.createUser();
      const r = await store.createPat({
        usrId: u.id,
        name: "cli",
        scope: ["admin"],
      });
      const verified = await store.verifyPatToken(r.token);
      expect(verified.patId).toBe(r.pat.id);
      expect(verified.usrId).toBe(u.id);
      expect(verified.scope).toEqual(["admin"]);
    });

    it("verifyPatToken updates lastUsedAt when coalescing disabled", async () => {
      const u = await store.createUser();
      const r = await store.createPat({ usrId: u.id, name: "cli", scope: [] });
      expect(r.pat.lastUsedAt).toBeNull();

      now = new Date(now.getTime() + 5_000);
      await store.verifyPatToken(r.token);
      const reread = await store.getPat(r.pat.id);
      expect(reread.lastUsedAt?.toISOString()).toBe(now.toISOString());
    });

    it("verifyPatToken throws InvalidPatTokenError for missing row", async () => {
      await expect(
        store.verifyPatToken(`pat_${"a".repeat(32)}_anysecret`),
      ).rejects.toThrow(InvalidPatTokenError);
    });

    it("verifyPatToken throws InvalidPatTokenError for wrong secret", async () => {
      const u = await store.createUser();
      const r = await store.createPat({ usrId: u.id, name: "cli", scope: [] });
      const idHex = r.pat.id.slice(4);
      await expect(
        store.verifyPatToken(`pat_${idHex}_wrongSecret`),
      ).rejects.toThrow(InvalidPatTokenError);
    });

    it("verifyPatToken throws PatRevokedError (ordered first)", async () => {
      const u = await store.createUser();
      const r = await store.createPat({
        usrId: u.id,
        name: "cli",
        scope: [],
        expiresAt: new Date("2026-06-01T00:00:00Z"),
      });
      await store.revokePat(r.pat.id);
      await expect(store.verifyPatToken(r.token)).rejects.toThrow(
        PatRevokedError,
      );
    });

    it("verifyPatToken throws PatExpiredError after expires_at", async () => {
      const u = await store.createUser();
      const r = await store.createPat({
        usrId: u.id,
        name: "cli",
        scope: [],
        expiresAt: new Date("2026-05-01T13:00:00Z"),
      });
      now = new Date(now.getTime() + 24 * 60 * 60 * 1000);
      await expect(store.verifyPatToken(r.token)).rejects.toThrow(
        PatExpiredError,
      );
    });

    it("revokePat is idempotent", async () => {
      const u = await store.createUser();
      const r = await store.createPat({ usrId: u.id, name: "cli", scope: [] });
      const first = await store.revokePat(r.pat.id);
      now = new Date(now.getTime() + 3_600_000);
      const second = await store.revokePat(r.pat.id);
      expect(second.revokedAt?.toISOString()).toBe(first.revokedAt?.toISOString());
    });

    it("revokePat throws NotFoundError for unknown patId", async () => {
      await expect(store.revokePat(generate("pat") as PatId)).rejects.toThrow(
        NotFoundError,
      );
    });

    it("listPatsForUser returns id-ordered PATs scoped to the user", async () => {
      const alice = await store.createUser();
      const bob = await store.createUser();
      await store.createPat({ usrId: alice.id, name: "a-1", scope: [] });
      await new Promise((r) => setTimeout(r, 2));
      await store.createPat({ usrId: alice.id, name: "a-2", scope: [] });
      await store.createPat({ usrId: bob.id, name: "bob-1", scope: [] });

      const page = await store.listPatsForUser(alice.id);
      expect(page.data.length).toBe(2);
      expect(page.data[0]!.name).toBe("a-1");
      expect(page.data[1]!.name).toBe("a-2");
    });

    it("listPatsForUser filters by status", async () => {
      const u = await store.createUser();
      const live = await store.createPat({
        usrId: u.id,
        name: "live",
        scope: [],
      });
      const rev = await store.createPat({ usrId: u.id, name: "rev", scope: [] });
      await store.revokePat(rev.pat.id);

      const activeOnly = await store.listPatsForUser(u.id, { status: "active" });
      expect(activeOnly.data.length).toBe(1);
      expect(activeOnly.data[0]!.id).toBe(live.pat.id);

      const revokedOnly = await store.listPatsForUser(u.id, {
        status: "revoked",
      });
      expect(revokedOnly.data.length).toBe(1);
      expect(revokedOnly.data[0]!.id).toBe(rev.pat.id);
    });

    it("coalesces lastUsedAt writes within the configured window", async () => {
      now = new Date("2026-05-01T12:00:00Z");
      const coalesceStore = new PostgresIdentityStore(pool, {
        clock: () => now,
        patLastUsedCoalesceSeconds: 60,
      });
      const u = await coalesceStore.createUser();
      const r = await coalesceStore.createPat({
        usrId: u.id,
        name: "cli",
        scope: [],
      });

      now = new Date(now.getTime() + 5_000);
      await coalesceStore.verifyPatToken(r.token);
      const after1 = (await coalesceStore.getPat(r.pat.id)).lastUsedAt;

      now = new Date(now.getTime() + 10_000);
      await coalesceStore.verifyPatToken(r.token);
      const after2 = (await coalesceStore.getPat(r.pat.id)).lastUsedAt;
      expect(after2?.toISOString()).toBe(after1?.toISOString());

      now = new Date(now.getTime() + 90_000);
      await coalesceStore.verifyPatToken(r.token);
      const after3 = (await coalesceStore.getPat(r.pat.id)).lastUsedAt;
      expect(after3?.toISOString()).not.toBe(after1?.toISOString());
    });

    it("cooperates with caller-owned PoolClient via SAVEPOINT (ADR 0013)", async () => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const txStore = new PostgresIdentityStore(client, {
          clock: () => now,
          patLastUsedCoalesceSeconds: 0,
        });
        const u = await txStore.createUser();
        const r = await txStore.createPat({
          usrId: u.id,
          name: "cli",
          scope: [],
        });
        await txStore.revokePat(r.pat.id);
        await client.query("COMMIT");

        const reread = await store.getPat(r.pat.id);
        expect(reread.status).toBe("revoked");
      } finally {
        client.release();
      }
    });

    it("rolls back inner failure without aborting the outer transaction", async () => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const txStore = new PostgresIdentityStore(client, {
          clock: () => now,
          patLastUsedCoalesceSeconds: 0,
        });
        const u = await txStore.createUser();
        await txStore.createPat({ usrId: u.id, name: "good", scope: [] });

        // Provoke a failure (revoked user) inside the same outer txn.
        const other = await txStore.createUser();
        await txStore.revokeUser(other.id);
        await expect(
          txStore.createPat({ usrId: other.id, name: "doomed", scope: [] }),
        ).rejects.toThrow(AlreadyTerminalError);

        // Outer txn still alive; can keep working.
        await txStore.createPat({ usrId: u.id, name: "after", scope: [] });
        await client.query("COMMIT");

        const page = await store.listPatsForUser(u.id);
        expect(page.data.length).toBe(2);
      } finally {
        client.release();
      }
    });
  },
);

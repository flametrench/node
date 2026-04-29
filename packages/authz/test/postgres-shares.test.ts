// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decode, generate } from "@flametrench/ids";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  InvalidFormatError,
  InvalidShareTokenError,
  PreconditionError,
  SHARE_MAX_TTL_SECONDS,
  ShareConsumedError,
  ShareExpiredError,
  ShareNotFoundError,
  ShareRevokedError,
  type ShrId,
  type UsrId,
} from "../src/index.js";

const POSTGRES_URL = process.env.AUTHZ_POSTGRES_URL;
const hasPostgres = Boolean(POSTGRES_URL);

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");

describe.skipIf(!hasPostgres)("PostgresShareStore", () => {
  let pool: Pool;
  // Imported lazily so the symbol exists only when the env var is set.
  let PostgresShareStore: typeof import("../src/postgres.js").PostgresShareStore;
  let store: import("../src/postgres.js").PostgresShareStore;
  let alice: UsrId;
  let project42: string;

  beforeAll(async () => {
    pool = new Pool({ connectionString: POSTGRES_URL });
    ({ PostgresShareStore } = await import("../src/postgres.js"));
  });

  afterAll(async () => {
    await pool.end();
  });

  async function registerUser(wire: UsrId): Promise<void> {
    await pool.query("INSERT INTO usr (id, status) VALUES ($1, 'active')", [
      decode(wire).uuid,
    ]);
  }

  beforeEach(async () => {
    await pool.query("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;");
    await pool.query(SCHEMA_SQL);
    store = new PostgresShareStore(pool);
    alice = generate("usr") as UsrId;
    await registerUser(alice);
    project42 = decode(generate("usr")).uuid;
  });

  it("createShare yields a fresh shr_ id and a token distinct from it", async () => {
    const result = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    expect(result.share.id).toMatch(/^shr_[0-9a-f]{32}$/);
    expect(result.token).not.toBe(result.share.id);
    expect(result.share.singleUse).toBe(false);
    expect(result.share.consumedAt).toBeNull();
  });

  it("rejects malformed relation", async () => {
    await expect(
      store.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "Viewer!",
        createdBy: alice,
        expiresInSeconds: 600,
      }),
    ).rejects.toThrow(InvalidFormatError);
  });

  it("rejects expiresInSeconds beyond the 365-day ceiling", async () => {
    await expect(
      store.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: SHARE_MAX_TTL_SECONDS + 1,
      }),
    ).rejects.toThrow(InvalidFormatError);
  });

  it("verifyShareToken round-trips for a valid token", async () => {
    const { share, token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const v = await store.verifyShareToken(token);
    expect(v.shareId).toBe(share.id);
    expect(v.objectType).toBe("proj");
    expect(v.objectId).toBe(project42);
    expect(v.relation).toBe("viewer");
  });

  it("verifyShareToken raises InvalidShareTokenError for unknown tokens", async () => {
    await expect(store.verifyShareToken("not-a-real-token")).rejects.toThrow(
      InvalidShareTokenError,
    );
  });

  it("verifyShareToken raises ShareRevokedError for revoked shares", async () => {
    const { share, token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    await store.revokeShare(share.id);
    await expect(store.verifyShareToken(token)).rejects.toThrow(
      ShareRevokedError,
    );
  });

  it("verifyShareToken raises ShareExpiredError when past expiry", async () => {
    let now = new Date("2026-04-27T00:00:00Z");
    const clock = () => now;
    const s = new PostgresShareStore(pool, { clock });
    const { token } = await s.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 60,
    });
    now = new Date(now.getTime() + 61 * 1000);
    await expect(s.verifyShareToken(token)).rejects.toThrow(ShareExpiredError);
  });

  it("single-use share consumes on first verify and rejects subsequent verifies", async () => {
    const { share, token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
      singleUse: true,
    });
    await store.verifyShareToken(token);
    const consumed = await store.getShare(share.id);
    expect(consumed.consumedAt).not.toBeNull();
    await expect(store.verifyShareToken(token)).rejects.toThrow(
      ShareConsumedError,
    );
  });

  it("non-single-use shares can be verified repeatedly", async () => {
    const { token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    await store.verifyShareToken(token);
    const second = await store.verifyShareToken(token);
    expect(second.relation).toBe("viewer");
  });

  it("revoked + expired share raises ShareRevokedError (revoke wins precedence)", async () => {
    let now = new Date("2026-04-27T00:00:00Z");
    const clock = () => now;
    const s = new PostgresShareStore(pool, { clock });
    const { share, token } = await s.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 60,
    });
    await s.revokeShare(share.id);
    now = new Date(now.getTime() + 61 * 1000);
    await expect(s.verifyShareToken(token)).rejects.toThrow(ShareRevokedError);
  });

  it("revokeShare is idempotent — second call returns the same revokedAt", async () => {
    const { share } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const first = await store.revokeShare(share.id);
    const ts = first.revokedAt!;
    const second = await store.revokeShare(share.id);
    expect(second.revokedAt!.toISOString()).toBe(ts.toISOString());
  });

  it("revokeShare raises ShareNotFoundError for unknown ids", async () => {
    await expect(store.revokeShare(generate("shr") as ShrId)).rejects.toThrow(
      ShareNotFoundError,
    );
  });

  it("getShare raises ShareNotFoundError for unknown ids", async () => {
    await expect(store.getShare(generate("shr") as ShrId)).rejects.toThrow(
      ShareNotFoundError,
    );
  });

  // ─── ADR 0012: created_by must be an active user ───

  it("rejects createShare when created_by user is suspended", async () => {
    await pool.query("UPDATE usr SET status = 'suspended' WHERE id = $1", [
      decode(alice).uuid,
    ]);
    await expect(
      store.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: 600,
      }),
    ).rejects.toThrow(PreconditionError);
  });

  it("rejects createShare when created_by user is revoked", async () => {
    await pool.query("UPDATE usr SET status = 'revoked' WHERE id = $1", [
      decode(alice).uuid,
    ]);
    await expect(
      store.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: 600,
      }),
    ).rejects.toThrow(PreconditionError);
  });

  it("rejects createShare when created_by user does not exist", async () => {
    const ghost = generate("usr") as UsrId;
    await expect(
      store.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: ghost,
        expiresInSeconds: 600,
      }),
    ).rejects.toThrow(PreconditionError);
  });

  // ─── Spec error precedence: consumed > expired ───

  it("consumed + expired share raises ShareConsumedError (consumed wins)", async () => {
    let now = new Date("2026-04-27T00:00:00Z");
    const clock = () => now;
    const s = new PostgresShareStore(pool, { clock });
    const { token } = await s.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 60,
      singleUse: true,
    });
    await s.verifyShareToken(token); // consumes
    now = new Date(now.getTime() + 61 * 1000); // now also expired
    await expect(s.verifyShareToken(token)).rejects.toThrow(
      ShareConsumedError,
    );
  });

  // ─── createdBy round-trip through Postgres ───

  it("createdBy round-trips through Postgres encode/decode", async () => {
    const { share } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const fetched = await store.getShare(share.id);
    expect(fetched.createdBy).toBe(alice);
    expect(fetched.createdBy).toMatch(/^usr_/);
  });

  // ─── Listing returns shares in every state ───

  it("listSharesForObject returns active, revoked, and consumed shares", async () => {
    const active = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const revoked = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const consumed = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
      singleUse: true,
    });
    await store.revokeShare(revoked.share.id);
    await store.verifyShareToken(consumed.token);
    const page = await store.listSharesForObject("proj", project42);
    const ids = new Set(page.data.map((s) => s.id));
    expect(ids.has(active.share.id)).toBe(true);
    expect(ids.has(revoked.share.id)).toBe(true);
    expect(ids.has(consumed.share.id)).toBe(true);
  });

  it("listSharesForObject filters by object and paginates", async () => {
    const otherProj = decode(generate("usr")).uuid;
    const ids: string[] = [];
    for (const obj of [project42, project42, otherProj, project42]) {
      const r = await store.createShare({
        objectType: "proj",
        objectId: obj,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: 600,
      });
      if (obj === project42) ids.push(r.share.id);
    }
    const page1 = await store.listSharesForObject("proj", project42, {
      limit: 2,
    });
    expect(page1.data).toHaveLength(2);
    expect(page1.nextCursor).not.toBeNull();
    const page2 = await store.listSharesForObject("proj", project42, {
      limit: 10,
      cursor: page1.nextCursor!,
    });
    const got = new Set([
      ...page1.data.map((s) => s.id),
      ...page2.data.map((s) => s.id),
    ]);
    expect(got.size).toBe(3);
    expect([...got].sort()).toEqual([...ids].sort());
  });

  // ───── Outer-transaction nesting (ADR 0013) ─────

  it("createShare cooperates with an outer transaction (no nested-BEGIN error)", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresShareStore(client);
      const r = await nested.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: 600,
      });
      await client.query("COMMIT");
      const fetched = await store.getShare(r.share.id);
      expect(fetched.id).toBe(r.share.id);
    } finally {
      client.release();
    }
  });

  it("rolling back an outer transaction undoes the inner createShare", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresShareStore(client);
      const r = await nested.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: 600,
      });
      await client.query("ROLLBACK");
      await expect(store.getShare(r.share.id)).rejects.toThrow(
        ShareNotFoundError,
      );
    } finally {
      client.release();
    }
  });

  it("verifyShareToken cooperates with an outer transaction", async () => {
    // Create the share outside, verify inside an outer transaction.
    const r = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresShareStore(client);
      const verified = await nested.verifyShareToken(r.token);
      expect(verified.shareId).toBe(r.share.id);
      await client.query("COMMIT");
    } finally {
      client.release();
    }
  });

  it("outer transaction can commit a second SDK call after first rolls back its savepoint (revoked share)", async () => {
    const r = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    await store.revokeShare(r.share.id);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresShareStore(client);
      await expect(nested.verifyShareToken(r.token)).rejects.toThrow(
        ShareRevokedError,
      );
      // Outer txn still usable.
      const r2 = await nested.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: 600,
      });
      await client.query("COMMIT");
      expect((await store.getShare(r2.share.id)).id).toBe(r2.share.id);
    } finally {
      client.release();
    }
  });
});

if (!hasPostgres) {
  // eslint-disable-next-line no-console
  console.log(
    "[postgres-shares.test.ts] AUTHZ_POSTGRES_URL not set; PostgresShareStore tests are skipped.",
  );
}

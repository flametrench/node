// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decode, generate } from "@flametrench/ids";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  DuplicateTupleError,
  EmptyRelationSetError,
  InvalidFormatError,
  TupleNotFoundError,
  type UsrId,
} from "../src/index.js";
import { PostgresTupleStore } from "../src/postgres.js";

const POSTGRES_URL = process.env.AUTHZ_POSTGRES_URL;
const hasPostgres = Boolean(POSTGRES_URL);

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");

function newUsr(): UsrId {
  return generate("usr") as UsrId;
}

/** Bare UUID (no Flametrench prefix) used as `object_id` for application objects. */
function newObjectId(): string {
  return decode(generate("usr")).uuid;
}

/**
 * The tup table's created_by column FKs to usr(id), so tests must
 * pre-register any UsrId they reference. In production the identity
 * layer owns the usr table; @flametrench/authz only manages tuples.
 */
async function registerUser(pool: Pool, usrId: UsrId): Promise<void> {
  await pool.query(`INSERT INTO usr (id, status) VALUES ($1, 'active')`, [
    decode(usrId).uuid,
  ]);
}

describe.skipIf(!hasPostgres)("PostgresTupleStore", () => {
  let pool: Pool;
  let store: PostgresTupleStore;
  let alice: UsrId;
  let bob: UsrId;
  let carol: UsrId;
  let project42: string;
  let project99: string;

  beforeAll(async () => {
    pool = new Pool({ connectionString: POSTGRES_URL });
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
    await pool.query(SCHEMA_SQL);
    store = new PostgresTupleStore(pool);
    alice = newUsr();
    bob = newUsr();
    carol = newUsr();
    project42 = newObjectId();
    project99 = newObjectId();
    await registerUser(pool, alice);
    await registerUser(pool, bob);
    await registerUser(pool, carol);
  });

  // ───── createTuple ─────

  it("creates a tuple and returns it with a fresh tup_ id", async () => {
    const t = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "owner",
      objectType: "proj",
      objectId: project42,
      createdBy: alice,
    });
    expect(t.id).toMatch(/^tup_[0-9a-f]{32}$/);
    expect(t.subjectId).toBe(alice);
    expect(t.createdBy).toBe(alice);
    expect(t.objectId).toBe(project42);
  });

  it("rejects a duplicate natural key with the existing tuple id attached", async () => {
    const first = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: project42,
    });
    try {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      expect.fail("expected DuplicateTupleError");
    } catch (err) {
      expect(err).toBeInstanceOf(DuplicateTupleError);
      expect((err as DuplicateTupleError).existingTupleId).toBe(first.id);
    }
  });

  it("rejects a malformed relation", async () => {
    await expect(
      store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "Owner!",
        objectType: "proj",
        objectId: project42,
      }),
    ).rejects.toThrow(InvalidFormatError);
  });

  it("rejects a malformed object_type", async () => {
    await expect(
      store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "owner",
        objectType: "Project",
        objectId: project42,
      }),
    ).rejects.toThrow(InvalidFormatError);
  });

  // ───── check / checkAny ─────

  it("check returns allowed=true with the matched tuple id", async () => {
    const t = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: project42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: project42,
    });
    expect(result.allowed).toBe(true);
    expect(result.matchedTupleId).toBe(t.id);
  });

  it("check returns allowed=false when no tuple matches", async () => {
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "owner",
      objectType: "proj",
      objectId: project42,
    });
    expect(result.allowed).toBe(false);
    expect(result.matchedTupleId).toBeNull();
  });

  it("checkAny matches any of the supplied relations", async () => {
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: project42,
    });
    const result = await store.checkAny({
      subjectType: "usr",
      subjectId: alice,
      relations: ["viewer", "editor", "owner"],
      objectType: "proj",
      objectId: project42,
    });
    expect(result.allowed).toBe(true);
  });

  it("checkAny rejects an empty relation set", async () => {
    await expect(
      store.checkAny({
        subjectType: "usr",
        subjectId: alice,
        relations: [],
        objectType: "proj",
        objectId: project42,
      }),
    ).rejects.toThrow(EmptyRelationSetError);
  });

  // ───── deleteTuple ─────

  it("deleteTuple removes the row; subsequent check is false", async () => {
    const t = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: project42,
    });
    await store.deleteTuple(t.id);
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: project42,
    });
    expect(result.allowed).toBe(false);
  });

  it("deleteTuple of an unknown id raises TupleNotFoundError", async () => {
    await expect(
      store.deleteTuple(generate("tup") as never),
    ).rejects.toThrow(TupleNotFoundError);
  });

  // ───── cascadeRevokeSubject ─────

  it("cascadeRevokeSubject deletes every tuple for that subject", async () => {
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: project42,
    });
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: project99,
    });
    await store.createTuple({
      subjectType: "usr",
      subjectId: bob,
      relation: "viewer",
      objectType: "proj",
      objectId: project42,
    });
    const removed = await store.cascadeRevokeSubject("usr", alice);
    expect(removed).toBe(2);
    const aliceTuples = await store.listTuplesBySubject("usr", alice);
    expect(aliceTuples.data).toEqual([]);
    const bobTuples = await store.listTuplesBySubject("usr", bob);
    expect(bobTuples.data).toHaveLength(1);
  });

  // ───── getTuple ─────

  it("getTuple round-trips a created tuple", async () => {
    const t = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "owner",
      objectType: "proj",
      objectId: project42,
      createdBy: alice,
    });
    const fetched = await store.getTuple(t.id);
    expect(fetched.id).toBe(t.id);
    expect(fetched.subjectId).toBe(alice);
    expect(fetched.relation).toBe("owner");
    expect(fetched.objectId).toBe(project42);
    expect(fetched.createdBy).toBe(alice);
  });

  it("getTuple raises TupleNotFoundError for unknown id", async () => {
    await expect(store.getTuple(generate("tup") as never)).rejects.toThrow(
      TupleNotFoundError,
    );
  });

  // ───── listTuplesByObject ─────

  it("listTuplesByObject filters by object and (optionally) relation", async () => {
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "owner",
      objectType: "proj",
      objectId: project42,
    });
    await store.createTuple({
      subjectType: "usr",
      subjectId: bob,
      relation: "viewer",
      objectType: "proj",
      objectId: project42,
    });
    await store.createTuple({
      subjectType: "usr",
      subjectId: carol,
      relation: "viewer",
      objectType: "proj",
      objectId: project99,
    });

    const allOnP42 = await store.listTuplesByObject("proj", project42);
    expect(allOnP42.data).toHaveLength(2);

    const viewersOnP42 = await store.listTuplesByObject(
      "proj",
      project42,
      "viewer",
    );
    expect(viewersOnP42.data).toHaveLength(1);
    expect(viewersOnP42.data[0]!.subjectId).toBe(bob);
  });

  // ───── Pagination ─────

  it("listTuplesBySubject paginates", async () => {
    const objects = Array.from({ length: 5 }, () => newObjectId());
    for (const o of objects) {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: o,
      });
    }
    const page1 = await store.listTuplesBySubject("usr", alice, { limit: 2 });
    expect(page1.data).toHaveLength(2);
    expect(page1.nextCursor).not.toBeNull();
    const page2 = await store.listTuplesBySubject("usr", alice, {
      limit: 10,
      cursor: page1.nextCursor!,
    });
    const all = [...page1.data, ...page2.data];
    expect(new Set(all.map((t) => t.id)).size).toBe(5);
  });

  // ───── spec#8: wire-format object_id with app-defined prefix ─────

  it("accepts wire-format object_id with an app-defined prefix (proj_<32hex>)", async () => {
    // ADR 0001 / spec/docs/authorization.md: object_type is application-
    // defined. Adopters legitimately pass wire-format prefixed IDs
    // (e.g. `proj_<32hex>`, `file_<32hex>`) at this boundary. Closes
    // spec#8 — previously this raised a Postgres UUID parse error.
    const wireProj = `proj_${newObjectId().replace(/-/g, "")}`;
    const t = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "owner",
      objectType: "proj",
      objectId: wireProj,
    });
    expect(t.id).toMatch(/^tup_[0-9a-f]{32}$/);
    // check() and listTuplesByObject() must accept the same wire-format
    // value back through the read paths.
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "owner",
      objectType: "proj",
      objectId: wireProj,
    });
    expect(result.allowed).toBe(true);
    const list = await store.listTuplesByObject("proj", wireProj);
    expect(list.data).toHaveLength(1);
  });

  // ───── Outer-transaction nesting (ADR 0013) ─────

  it("createTuple cooperates with an outer transaction (no nested-BEGIN error)", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresTupleStore(client);
      const t = await nested.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      await client.query("COMMIT");
      const r = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      expect(r.allowed).toBe(true);
      expect(t.id).toMatch(/^tup_[0-9a-f]{32}$/);
    } finally {
      client.release();
    }
  });

  it("rolling back an outer transaction undoes the inner createTuple", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresTupleStore(client);
      await nested.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      await client.query("ROLLBACK");
      const r = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      expect(r.allowed).toBe(false);
    } finally {
      client.release();
    }
  });

  it("outer transaction can commit a second SDK call after first rolls back its savepoint (duplicate tuple)", async () => {
    // Seed a tuple so the next createTuple with the same natural key conflicts.
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: project42,
    });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresTupleStore(client);
      await expect(
        nested.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "proj",
          objectId: project42,
        }),
      ).rejects.toThrow(DuplicateTupleError);
      // Outer txn still usable — savepoint rolled back the duplicate.
      const survivor = await nested.createTuple({
        subjectType: "usr",
        subjectId: bob,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      await client.query("COMMIT");
      expect(survivor.subjectId).toBe(bob);
    } finally {
      client.release();
    }
  });

  it("multiple SDK calls in one outer transaction commit-or-rollback together", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const nested = new PostgresTupleStore(client);
      await nested.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      await nested.createTuple({
        subjectType: "usr",
        subjectId: bob,
        relation: "viewer",
        objectType: "proj",
        objectId: project99,
      });
      await client.query("ROLLBACK");
      const a = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      const b = await store.check({
        subjectType: "usr",
        subjectId: bob,
        relation: "viewer",
        objectType: "proj",
        objectId: project99,
      });
      expect(a.allowed).toBe(false);
      expect(b.allowed).toBe(false);
    } finally {
      client.release();
    }
  });
});

if (!hasPostgres) {
  // eslint-disable-next-line no-console
  console.log(
    "[postgres.test.ts] AUTHZ_POSTGRES_URL not set; PostgresTupleStore tests are skipped.\n" +
      "  Set e.g. `AUTHZ_POSTGRES_URL=postgresql://postgres:test@localhost:5432/flametrench_test` " +
      "with a reachable Postgres 16+ instance to run them.",
  );
}

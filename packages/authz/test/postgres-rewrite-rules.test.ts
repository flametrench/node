// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// PostgresTupleStore rewrite-rule evaluation per ADR 0017.
// Mirrors the in-memory rewrite-rules tests so any drift between the
// two implementations surfaces as a failing test.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decode, generate } from "@flametrench/ids";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  EvaluationLimitExceededError,
  type Rules,
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

function newObjectId(): string {
  return decode(generate("usr")).uuid;
}

async function registerUser(pool: Pool, usrId: UsrId): Promise<void> {
  await pool.query(`INSERT INTO usr (id, status) VALUES ($1, 'active')`, [
    decode(usrId).uuid,
  ]);
}

describe.skipIf(!hasPostgres)(
  "PostgresTupleStore — rewrite rules (ADR 0017)",
  () => {
    let pool: Pool;
    let alice: UsrId;
    let proj42: string;
    let orgAcme: string;

    beforeAll(async () => {
      pool = new Pool({ connectionString: POSTGRES_URL });
    });

    afterAll(async () => {
      await pool.end();
    });

    beforeEach(async () => {
      await pool.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
      await pool.query(SCHEMA_SQL);
      alice = newUsr();
      proj42 = newObjectId();
      orgAcme = newObjectId();
      await registerUser(pool, alice);
    });

    describe("empty rules → v0.2-equivalent behavior", () => {
      it("undefined rules: no derivation", async () => {
        const store = new PostgresTupleStore(pool); // rules undefined
        await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "editor",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.check({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(false);
      });

      it("empty rules object: no derivation", async () => {
        const store = new PostgresTupleStore(pool, { rules: {} });
        await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "editor",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.check({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(false);
      });
    });

    describe("computed_userset (role implication)", () => {
      it("editor implies viewer", async () => {
        const rules: Rules = {
          proj: {
            viewer: [
              { type: "this" },
              { type: "computed_userset", relation: "editor" },
            ],
          },
        };
        const store = new PostgresTupleStore(pool, { rules });
        const editorTup = await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "editor",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.check({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(true);
        expect(result.matchedTupleId).toBe(editorTup.id);
      });

      it("admin → editor → viewer chain", async () => {
        const rules: Rules = {
          proj: {
            viewer: [
              { type: "this" },
              { type: "computed_userset", relation: "editor" },
            ],
            editor: [
              { type: "this" },
              { type: "computed_userset", relation: "admin" },
            ],
          },
        };
        const store = new PostgresTupleStore(pool, { rules });
        const adminTup = await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "admin",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.check({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(true);
        expect(result.matchedTupleId).toBe(adminTup.id);
      });

      it("missing intermediate rule breaks the chain", async () => {
        const rules: Rules = {
          proj: {
            viewer: [
              { type: "this" },
              { type: "computed_userset", relation: "editor" },
            ],
          },
        };
        const store = new PostgresTupleStore(pool, { rules });
        await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "admin",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.check({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(false);
      });
    });

    describe("tuple_to_userset (parent-child inheritance)", () => {
      it("org admin implies proj admin via parent_org", async () => {
        const rules: Rules = {
          proj: {
            admin: [
              { type: "this" },
              {
                type: "tuple_to_userset",
                tuplesetRelation: "parent_org",
                computedUsersetRelation: "admin",
              },
            ],
          },
        };
        const store = new PostgresTupleStore(pool, { rules });
        const orgAdminTup = await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "admin",
          objectType: "org",
          objectId: orgAcme,
        });
        await store.createTuple({
          subjectType: "org" as never,
          subjectId: orgAcme as UsrId,
          relation: "parent_org",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.check({
          subjectType: "usr",
          subjectId: alice,
          relation: "admin",
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(true);
        expect(result.matchedTupleId).toBe(orgAdminTup.id);
      });

      it("org member does NOT imply proj admin", async () => {
        const rules: Rules = {
          proj: {
            admin: [
              { type: "this" },
              {
                type: "tuple_to_userset",
                tuplesetRelation: "parent_org",
                computedUsersetRelation: "admin",
              },
            ],
          },
        };
        const store = new PostgresTupleStore(pool, { rules });
        await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "member",
          objectType: "org",
          objectId: orgAcme,
        });
        await store.createTuple({
          subjectType: "org" as never,
          subjectId: orgAcme as UsrId,
          relation: "parent_org",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.check({
          subjectType: "usr",
          subjectId: alice,
          relation: "admin",
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(false);
      });
    });

    describe("cycle detection", () => {
      it("self-referential cycle terminates silently", async () => {
        const rules: Rules = {
          proj: {
            viewer: [
              { type: "this" },
              { type: "computed_userset", relation: "viewer" },
            ],
          },
        };
        const store = new PostgresTupleStore(pool, { rules });
        const result = await store.check({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(false);
      });
    });

    describe("evaluation bounds", () => {
      it("depth limit raises EvaluationLimitExceededError", async () => {
        // 4-step chain: viewer → editor → admin → owner → super.
        // Set maxDepth=2 so we hit the bound during expansion.
        const rules: Rules = {
          proj: {
            viewer: [{ type: "computed_userset", relation: "editor" }],
            editor: [{ type: "computed_userset", relation: "admin" }],
            admin: [{ type: "computed_userset", relation: "owner" }],
            owner: [{ type: "computed_userset", relation: "super" }],
          },
        };
        const store = new PostgresTupleStore(pool, { rules, maxDepth: 2 });
        await expect(
          store.check({
            subjectType: "usr",
            subjectId: alice,
            relation: "viewer",
            objectType: "proj",
            objectId: proj42,
          }),
        ).rejects.toBeInstanceOf(EvaluationLimitExceededError);
      });
    });

    describe("checkAny()", () => {
      it("fast path with no rules: single SQL query short-circuits", async () => {
        const store = new PostgresTupleStore(pool);
        await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "editor",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.checkAny({
          subjectType: "usr",
          subjectId: alice,
          relations: ["viewer", "editor"],
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(true);
      });

      it("with rules: evaluates each relation in turn", async () => {
        const rules: Rules = {
          proj: {
            viewer: [
              { type: "this" },
              { type: "computed_userset", relation: "editor" },
            ],
          },
        };
        const store = new PostgresTupleStore(pool, { rules });
        await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "editor",
          objectType: "proj",
          objectId: proj42,
        });
        const result = await store.checkAny({
          subjectType: "usr",
          subjectId: alice,
          // 'admin' has no rule and no tuple → denied. 'viewer' evaluates
          // via rule, hits editor → allowed.
          relations: ["admin", "viewer"],
          objectType: "proj",
          objectId: proj42,
        });
        expect(result.allowed).toBe(true);
      });
    });
  },
);

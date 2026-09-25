// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// authorization/shares/created-by-status.json. Per the fixture, this runs
// ONLY against Postgres (in-memory share stores have no usr table), with the
// identity ops create_user / revoke_user executed by PostgresIdentityStore
// against the same database.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { PostgresIdentityStore } from "../../identity/src/postgres.js";
import { PostgresShareStore } from "../src/postgres.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");
const POSTGRES_URL = process.env.AUTHZ_POSTGRES_URL;

interface Step {
  op: string;
  input: Record<string, unknown>;
  captures?: Record<string, string>;
  expected?: { error?: string };
}
interface FixtureTest {
  id: string;
  description: string;
  steps: Step[];
}

const fixture = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "authorization/shares/created-by-status.json"), "utf8"),
) as { tests: FixtureTest[] };

describe.skipIf(!POSTGRES_URL)("[postgres] authorization.create_share (authorization/shares/created-by-status.json)", () => {
  let pool: Pool;
  beforeAll(() => {
    pool = new Pool({ connectionString: POSTGRES_URL });
  });
  afterAll(async () => {
    await pool.end();
  });

  for (const t of fixture.tests) {
    it(`[${t.id}] ${t.description}`, async () => {
      await pool.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
      await pool.query(SCHEMA_SQL);
      const identity = new PostgresIdentityStore(pool);
      const shares = new PostgresShareStore(pool);
      const vars: Record<string, string> = {};
      const sub = (v: unknown): unknown =>
        typeof v === "string" ? v.replace(/\{(\w+)\}/g, (_, n: string) => vars[n] ?? `{${n}}`) : v;

      for (const [i, step] of t.steps.entries()) {
        const a = Object.fromEntries(Object.entries(step.input).map(([k, v]) => [k, sub(v)]));
        const expectedError = step.expected?.error;
        let result: unknown;
        try {
          switch (step.op) {
            case "create_user":
              result = { user: await identity.createUser({}) };
              break;
            case "revoke_user":
              result = { user: await identity.revokeUser(a.usr_id as `usr_${string}`) };
              break;
            case "create_share":
              result = await shares.createShare({
                objectType: a.object_type as string,
                objectId: a.object_id as string,
                relation: a.relation as string,
                createdBy: a.created_by as `usr_${string}`,
                expiresInSeconds: a.expires_in_seconds as number,
              });
              break;
            default:
              throw new Error(`Unknown fixture op: ${step.op}`);
          }
        } catch (err) {
          const e = err as Error;
          if (!expectedError) throw err;
          expect(
            e.constructor.name,
            `step ${i} '${step.op}': expected ${expectedError}, got ${e.constructor.name}: ${e.message}`,
          ).toBe(expectedError);
          return;
        }
        if (expectedError) {
          throw new Error(`step ${i} '${step.op}': expected ${expectedError} but the call succeeded`);
        }
        if (step.captures?.usr_id) {
          vars.usr_id = (result as { user: { id: string } }).user.id;
        }
      }
    });
  }
});

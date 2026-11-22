// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// State-machine harness for tenancy/revoke-invitation-authz.json and
// tenancy/revoke-invitation-as-system.json, run against
// BOTH InMemoryTenancyStore and PostgresTenancyStore (the latter only when
// TENANCY_POSTGRES_URL is set). Declared `users` get fresh usr_ ids; on
// Postgres they are also inserted into `usr` so membership FKs resolve.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decode, generate } from "@flametrench/ids";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  InMemoryTenancyStore,
  type MemId,
  type OrgId,
  type Role,
  type TenancyStore,
  type UsrId,
} from "../src/index.js";
import { PostgresTenancyStore } from "../src/postgres.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");
const POSTGRES_URL = process.env.TENANCY_POSTGRES_URL;

interface Step {
  op: string;
  input: Record<string, unknown>;
  captures?: Record<string, string>;
  expected?: { error?: string };
}
interface FixtureTest {
  id: string;
  description: string;
  users?: string[];
  steps: Step[];
}

const FIXTURES = [
  ["tenancy.revoke_invitation", "tenancy/revoke-invitation-authz.json"],
  ["tenancy.revoke_invitation_as_system", "tenancy/revoke-invitation-as-system.json"],
] as const;

function loadFixture(file: string): { tests: FixtureTest[] } {
  return JSON.parse(readFileSync(join(FIXTURES_DIR, file), "utf8")) as { tests: FixtureTest[] };
}

function resolveVars(value: unknown, vars: Record<string, unknown>): unknown {
  if (typeof value === "string") {
    const m = /^\{([a-z_][a-z0-9_]*)\}$/.exec(value);
    if (!m) return value;
    if (!(m[1]! in vars)) throw new Error(`Unknown variable {${m[1]}}`);
    return vars[m[1]!];
  }
  if (Array.isArray(value)) return value.map((v) => resolveVars(v, vars));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, resolveVars(v, vars)]),
    );
  }
  return value;
}

function walk(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const seg of path.split(".")) {
    const camel = seg.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
    const rec = cur as Record<string, unknown>;
    if (cur == null || typeof cur !== "object") throw new Error(`Cannot walk '${path}'`);
    if (seg in rec) cur = rec[seg];
    else if (camel in rec) cur = rec[camel];
    else throw new Error(`Cannot resolve '${seg}' in '${path}'`);
  }
  return cur;
}

async function invoke(s: TenancyStore, op: string, a: Record<string, unknown>): Promise<unknown> {
  switch (op) {
    case "create_org":
      return s.createOrg({ creator: a.creator as UsrId });
    case "add_member":
      return s.addMember({ orgId: a.org_id as OrgId, usrId: a.usr_id as UsrId, role: a.role as Role });
    case "suspend_membership":
      return s.suspendMembership(a.mem_id as MemId);
    case "create_invitation":
      return s.createInvitation({
        orgId: a.org_id as OrgId,
        identifier: a.identifier as string,
        role: a.role as Role,
        invitedBy: a.invited_by as UsrId,
        expiresAt: new Date(Date.now() + (a.ttl_seconds as number) * 1000),
      });
    case "revoke_invitation":
      return s.revokeInvitation({ invId: a.inv_id as `inv_${string}`, adminUsrId: a.admin_usr_id as UsrId });
    case "revoke_invitation_as_system":
      return s.revokeInvitationAsSystem(a.inv_id as `inv_${string}`);
    case "assert_invitation_status": {
      const inv = await s.getInvitation(a.inv_id as `inv_${string}`);
      expect(inv.status, "invitation status").toBe(a.expected_status);
      return null;
    }
    case "assert_equal":
      expect(a.actual).toBe(a.expected);
      return null;
    default:
      throw new Error(`Unknown fixture op: ${op}`);
  }
}

async function runTest(
  s: TenancyStore,
  t: FixtureTest,
  registerUser: (u: UsrId) => Promise<void>,
): Promise<void> {
  const vars: Record<string, unknown> = {};
  for (const name of t.users ?? []) {
    const id = generate("usr") as UsrId;
    await registerUser(id);
    vars[name] = id;
  }
  for (const [i, step] of t.steps.entries()) {
    const inp = resolveVars(step.input, vars) as Record<string, unknown>;
    const expectedError = step.expected?.error;
    let result: unknown;
    try {
      result = await invoke(s, step.op, inp);
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
    for (const [name, path] of Object.entries(step.captures ?? {})) {
      vars[name] = walk(result, path);
    }
  }
}

for (const [name, file] of FIXTURES) {
  const fixture = loadFixture(file);

  describe(`[in-memory] ${name} (${file})`, () => {
    for (const t of fixture.tests) {
      it(`[${t.id}] ${t.description}`, async () => {
        await runTest(new InMemoryTenancyStore(), t, async () => {});
      });
    }
  });

  describe.skipIf(!POSTGRES_URL)(`[postgres] ${name} (${file})`, () => {
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
        await runTest(new PostgresTenancyStore(pool), t, async (u) => {
          await pool.query(`INSERT INTO usr (id, status) VALUES ($1, 'active')`, [decode(u).uuid]);
        });
      });
    }
  });
}

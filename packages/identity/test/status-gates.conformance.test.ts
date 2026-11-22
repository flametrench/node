// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Step-DSL harness for the identity status-gate and TOTP-replay fixtures, run
// against BOTH InMemoryIdentityStore and PostgresIdentityStore (the latter only
// when IDENTITY_POSTGRES_URL is set). Harness pseudo-ops per the fixture
// descriptions: set_clock, compute_totp_code.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  InMemoryIdentityStore,
  totpCompute,
  type IdentityStore,
  type MfaProof,
} from "../src/index.js";
import { PostgresIdentityStore } from "../src/postgres.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");
const POSTGRES_URL = process.env.IDENTITY_POSTGRES_URL;

interface Step {
  op: string;
  input?: Record<string, unknown>;
  captures?: Record<string, string>;
  expected?: { error?: string };
}
interface FixtureTest {
  id: string;
  description: string;
  steps: Step[];
}
interface FixtureFile {
  capability: string;
  operation: string;
  conformance_level: string;
  tests: FixtureTest[];
}

function loadFixture(rel: string): FixtureFile {
  return JSON.parse(readFileSync(join(FIXTURES_DIR, rel), "utf8")) as FixtureFile;
}

function interpolate(value: unknown, vars: Map<string, string>): unknown {
  if (typeof value === "string") {
    return value.replace(/\{(\w+)\}/g, (_, n: string) => {
      const v = vars.get(n);
      if (v === undefined) throw new Error(`Unknown variable {${n}}`);
      return v;
    });
  }
  if (Array.isArray(value)) return value.map((v) => interpolate(v, vars));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, interpolate(v, vars)]),
    );
  }
  return value;
}

function walk(obj: unknown, path: string): string {
  let cur: unknown = obj;
  for (const seg of path.split(".")) {
    const camel = seg.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
    const rec = cur as Record<string, unknown>;
    if (cur == null || typeof cur !== "object") throw new Error(`Cannot walk '${path}'`);
    cur = seg in rec ? rec[seg] : rec[camel];
  }
  if (cur == null) throw new Error(`Capture path '${path}' resolved to null`);
  return String(cur);
}

function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.replace(/=+$/, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base32 char '${ch}'`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

interface Harness {
  store: IdentityStore;
  clock: { now: Date };
}

async function invoke(h: Harness, op: string, inp: Record<string, unknown>): Promise<unknown> {
  const s = h.store;
  switch (op) {
    case "set_clock":
      h.clock.now = new Date(inp.now as string);
      return null;
    case "create_user":
      return { user: await s.createUser({}) };
    case "create_user_with_password_credential": {
      const user = await s.createUser({});
      const credential = await s.createCredential({
        type: "password",
        usrId: user.id,
        identifier: inp.identifier as string,
        password: inp.password as string,
      });
      return { user, credential };
    }
    case "suspend_user":
      return { user: await s.suspendUser(inp.usr_id as `usr_${string}`) };
    case "reinstate_user":
      return { user: await s.reinstateUser(inp.usr_id as `usr_${string}`) };
    case "revoke_user":
      // Fixture contract: revokeUser ONLY — no extra cascade call.
      return { user: await s.revokeUser(inp.usr_id as `usr_${string}`) };
    case "verify_password":
      return s.verifyPassword({
        type: "password",
        identifier: inp.identifier as string,
        password: inp.password as string,
      });
    case "create_session":
      return s.createSession({
        usrId: inp.usr_id as `usr_${string}`,
        credId: inp.cred_id as `cred_${string}`,
        ttlSeconds: inp.ttl_seconds as number,
      });
    case "create_pat":
      return s.createPat({
        usrId: inp.usr_id as `usr_${string}`,
        name: inp.name as string,
        scope: inp.scope as string[],
      });
    case "verify_pat_token":
      return s.verifyPatToken(inp.token as string);
    case "enroll_totp_factor": {
      const r = await s.enrollTotpFactor(inp.usr_id as `usr_${string}`, "authenticator");
      return { factor: r.factor, secret: r.secretB32 };
    }
    case "compute_totp_code": {
      const ts = Math.floor(h.clock.now.getTime() / 1000);
      return { code: totpCompute(base32Decode(inp.secret as string), ts) };
    }
    case "confirm_totp_factor":
      return s.confirmTotpFactor(inp.mfa_id as string, inp.code as string);
    case "verify_mfa":
      return s.verifyMfa(inp.usr_id as `usr_${string}`, inp.proof as MfaProof);
    default:
      throw new Error(`Unknown fixture op: ${op}`);
  }
}

async function runTest(h: Harness, t: FixtureTest): Promise<void> {
  const vars = new Map<string, string>();
  for (const [i, step] of t.steps.entries()) {
    const inp = interpolate(step.input ?? {}, vars) as Record<string, unknown>;
    const expectedError = step.expected?.error;
    let result: unknown;
    try {
      result = await invoke(h, step.op, inp);
    } catch (err) {
      const e = err as Error;
      if (!expectedError) throw err;
      expect(
        e.constructor.name,
        `step ${i} '${step.op}': expected ${expectedError}, got ${e.constructor.name} (name=${e.name}): ${e.message}`,
      ).toBe(expectedError);
      return; // state-machine format: a test ends at its expected error
    }
    if (expectedError) {
      throw new Error(`step ${i} '${step.op}': expected ${expectedError} but the call succeeded`);
    }
    for (const [name, path] of Object.entries(step.captures ?? {})) {
      vars.set(name, walk(result, path));
    }
  }
}

const FIXTURES = [
  "identity/user-status-gates.json",
  "identity/mfa/totp-replay-rejected.json",
];

function registerSuite(
  storeName: string,
  makeStore: (clock: () => Date) => Promise<IdentityStore>,
): void {
  for (const file of FIXTURES) {
    const fixture = loadFixture(file);
    describe(`[${storeName}] ${fixture.capability}.${fixture.operation} (${file})`, () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, async () => {
          const clock = { now: new Date() };
          const store = await makeStore(() => clock.now);
          await runTest({ store, clock }, t);
        });
      }
    });
  }
}

registerSuite("in-memory", async (clock) => new InMemoryIdentityStore({ clock }));

describe.skipIf(!POSTGRES_URL)("postgres", () => {
  let pool: Pool;
  beforeAll(() => {
    pool = new Pool({ connectionString: POSTGRES_URL });
  });
  afterAll(async () => {
    await pool.end();
  });
  registerSuite("postgres", async (clock) => {
    await pool.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
    await pool.query(SCHEMA_SQL);
    return new PostgresIdentityStore(pool, { clock });
  });
});

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.4 conformance suite — Node / TypeScript harness for
// the audit capability (ADR 0019).
//
// Fixture format: step-DSL with {varname} interpolation and captures.
// Result matching is SUPERSET (result ⊇ expected): every field listed in
// expected must appear in the actual result with the same value.
//
// `occurred_at` / `recorded_at` are Date objects in the store; the harness
// serializes to ISO strings before comparison (toWire).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { generate } from "@flametrench/ids";
import { describe, expect, it } from "vitest";

import {
  InMemoryAuditStore,
  type AuditAuth,
  type AuditContext,
  type AuditEvent,
  type AuditId,
  type AuditOnBehalf,
  type AuditScope,
  type AuditTarget,
  type Outcome,
  type UsrId,
  type WriteAuditInput,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");

// ─── Fixture types ───

interface FixtureFile {
  spec_version: string;
  capability: string;
  conformance_level: string;
  description: string;
  tests: FixtureTest[];
}

interface FixtureTest {
  id: string;
  description: string;
  users?: string[];
  steps: Step[];
}

interface Step {
  op: string;
  input: Record<string, unknown>;
  captures?: Record<string, string>;
  expected?: { result?: Record<string, unknown>; error?: string };
}

// ─── Variable interpolation ───

const VAR_PATTERN = /^\{([a-z_][a-z0-9_]*)\}$/;

function resolveVars(value: unknown, vars: Record<string, unknown>): unknown {
  if (typeof value === "string") {
    const m = VAR_PATTERN.exec(value);
    if (m) {
      const name = m[1]!;
      if (!(name in vars)) throw new Error(`Unknown variable: {${name}}`);
      return vars[name];
    }
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => resolveVars(v, vars));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveVars(v, vars);
    return out;
  }
  return value;
}

// ─── Capture path resolution ───

function toCamel(s: string): string {
  return s.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

function walkPath(obj: unknown, path: string): unknown {
  let cur = obj;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object") throw new Error(`Cannot walk into non-object at '${seg}'`);
    const rec = cur as Record<string, unknown>;
    const camel = toCamel(seg);
    if (seg in rec) cur = rec[seg];
    else if (camel in rec) cur = rec[camel];
    else throw new Error(`Cannot resolve path segment '${seg}'`);
  }
  return cur;
}

// ─── Wire serialization (AuditEvent → snake_case plain object) ───

function toWire(event: AuditEvent): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: event.id,
    occurred_at: event.occurredAt.toISOString(),
    recorded_at: event.recordedAt.toISOString(),
    actor_usr_id: event.actorUsrId,
    action: event.action,
    target: event.target,
    outcome: event.outcome,
    metadata: event.metadata,
  };

  if (event.auth !== undefined) {
    const a = event.auth;
    const auth: Record<string, unknown> = { kind: a.kind };
    if (a.sessionId !== undefined) auth.session_id = a.sessionId;
    if (a.patId !== undefined) auth.pat_id = a.patId;
    if (a.shareId !== undefined) auth.share_id = a.shareId;
    if (a.systemId !== undefined) auth.system_id = a.systemId;
    out.auth = auth;
  }

  if (event.onBehalf !== undefined) {
    out.on_behalf = { agent_id: event.onBehalf.agentId };
  }

  if (event.scope !== undefined) {
    out.scope = event.scope;
  }

  if (event.context !== undefined) {
    const ctx: Record<string, unknown> = {};
    if (event.context.requestId !== undefined) ctx.request_id = event.context.requestId;
    if (event.context.ip !== undefined) ctx.ip = event.context.ip;
    if (event.context.userAgent !== undefined) ctx.user_agent = event.context.userAgent;
    out.context = ctx;
  }

  return out;
}

// ─── Superset assertion (result ⊇ expected) ───

function assertSubset(expected: unknown, actual: unknown, path: string): void {
  if (expected === null) {
    expect(actual, `${path} should be null`).toBeNull();
    return;
  }
  if (typeof expected !== "object") {
    expect(actual, `${path}`).toBe(expected);
    return;
  }
  expect(actual, `${path} should be an object`).not.toBeNull();
  expect(typeof actual, `${path} should be an object`).toBe("object");
  for (const [k, v] of Object.entries(expected as Record<string, unknown>)) {
    assertSubset(v, (actual as Record<string, unknown>)[k], `${path}.${k}`);
  }
}

// ─── Input deserialization (fixture wire → WriteAuditInput) ───

function parseAuth(raw: Record<string, unknown>): AuditAuth {
  const auth: AuditAuth = { kind: raw.kind as AuditAuth["kind"] };
  if (raw.session_id !== undefined) auth.sessionId = raw.session_id as `ses_${string}`;
  if (raw.pat_id !== undefined) auth.patId = raw.pat_id as `pat_${string}`;
  if (raw.share_id !== undefined) auth.shareId = raw.share_id as `shr_${string}`;
  if (raw.system_id !== undefined) auth.systemId = raw.system_id as string;
  return auth;
}

function parseContext(raw: Record<string, unknown>): AuditContext {
  const ctx: AuditContext = {};
  if (raw.request_id !== undefined) ctx.requestId = raw.request_id as string;
  if (raw.ip !== undefined) ctx.ip = raw.ip as string;
  if (raw.user_agent !== undefined) ctx.userAgent = raw.user_agent as string;
  return ctx;
}

function parseWriteInput(raw: Record<string, unknown>): WriteAuditInput {
  const inp: WriteAuditInput = {
    occurredAt: new Date(raw.occurred_at as string),
    actorUsrId: raw.actor_usr_id as UsrId | null,
    action: raw.action as string,
    target: raw.target as AuditTarget,
    outcome: raw.outcome as Outcome,
    metadata: (raw.metadata ?? {}) as Record<string, unknown>,
  };
  if (raw.auth !== undefined) inp.auth = parseAuth(raw.auth as Record<string, unknown>);
  if (raw.on_behalf !== undefined) {
    const ob = raw.on_behalf as Record<string, unknown>;
    inp.onBehalf = { agentId: ob.agent_id as string } satisfies AuditOnBehalf;
  }
  if (raw.scope !== undefined) inp.scope = raw.scope as AuditScope;
  if (raw.context !== undefined) inp.context = parseContext(raw.context as Record<string, unknown>);
  return inp;
}

// ─── Op dispatcher ───

async function invokeOp(
  store: InMemoryAuditStore,
  op: string,
  raw: Record<string, unknown>,
): Promise<unknown> {
  switch (op) {
    case "write": {
      const event = await store.write(parseWriteInput(raw));
      return toWire(event);
    }
    case "get": {
      const event = await store.get(raw.id as AuditId);
      return toWire(event);
    }
    default:
      throw new Error(`Unknown fixture op: ${op}`);
  }
}

// ─── Test runner ───

async function runTest(test: FixtureTest): Promise<void> {
  const store = new InMemoryAuditStore();
  const vars: Record<string, unknown> = {};

  for (const name of test.users ?? []) {
    vars[name] = generate("usr");
  }

  for (const step of test.steps) {
    const input = resolveVars(step.input, vars) as Record<string, unknown>;
    const result = await invokeOp(store, step.op, input);

    if (step.captures) {
      for (const [name, path] of Object.entries(step.captures)) {
        vars[name] = walkPath(result, path);
      }
    }

    if (step.expected?.result) {
      const expected = resolveVars(step.expected.result, vars);
      assertSubset(expected, result, "result");
    }
  }

  expect(true).toBe(true);
}

// ─── Test factories ───

const fixture = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "audit/write-event-shape.json"), "utf8"),
) as FixtureFile;

describe(`Conformance · audit.write [${fixture.conformance_level}]`, () => {
  for (const t of fixture.tests) {
    it(`[${t.id}] ${t.description}`, async () => {
      await runTest(t);
    });
  }
});

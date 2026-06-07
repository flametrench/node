// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.4 conformance suite — Node / TypeScript harness for
// the notifications capability (ADR 0022, Option 2).
//
// Fixture format: step-DSL with {varname} interpolation and captures.
// Result matching is SUPERSET (result ⊇ expected).
// Dates are serialized to ISO strings via toWire() before comparison.
//
// Harness note: lifecycle-shape.json ops (get/mark_read/mark_unread/dismiss)
// omit recipient_usr_id in their inputs — that field is landing shortly in
// a lifecycle-shape update. Until then the harness falls back to vars.recipient
// so the positive lifecycle vectors continue to pass unchanged.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { generate } from "@flametrench/ids";
import { describe, expect, it } from "vitest";

import {
  InMemoryNotifyStore,
  type CreateNotificationInput,
  type NotId,
  type OrgId,
  type UsrId,
} from "../src/index.js";
import type { Notification } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");

// ─── Fixture types ───

interface FixtureFile {
  spec_version: string;
  capability: string;
  conformance_level: string;
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

// ─── Wire serialization (Notification → snake_case plain object) ───

function toWire(n: Notification): Record<string, unknown> {
  return {
    id: n.id,
    scope: n.scope,
    recipient_usr_id: n.recipientUsrId,
    type: n.type,
    subject: n.subject,
    data: n.data,
    state: n.state,
    created_at: n.createdAt.toISOString(),
    state_changed_at: n.stateChangedAt.toISOString(),
  };
}

// ─── Superset assertion (result ⊇ expected) ───

function assertSubset(expected: unknown, actual: unknown, path: string): void {
  if (expected === null) {
    expect(actual, `${path} should be null`).toBeNull();
    return;
  }
  if (typeof expected !== "object") {
    expect(actual, path).toBe(expected);
    return;
  }
  expect(actual, `${path} should be object`).not.toBeNull();
  expect(typeof actual, `${path} should be object`).toBe("object");
  for (const [k, v] of Object.entries(expected as Record<string, unknown>)) {
    assertSubset(v, (actual as Record<string, unknown>)[k], `${path}.${k}`);
  }
}

// ─── Op dispatcher ───

async function invokeOp(
  store: InMemoryNotifyStore,
  op: string,
  raw: Record<string, unknown>,
  vars: Record<string, unknown>,
): Promise<unknown> {
  // recipient_usr_id fallback: lifecycle-shape ops omit it pending fixture update.
  // Falls back to vars.recipient so positive lifecycle vectors pass unchanged.
  const recipientUsrId = (raw.recipient_usr_id ?? vars["recipient"]) as UsrId;

  switch (op) {
    case "create_notification": {
      const n = await store.createNotification({
        scope: raw.scope as OrgId,
        recipientUsrId: raw.recipient_usr_id as UsrId,
        type: raw.type as string,
        subject: raw.subject as CreateNotificationInput["subject"],
        data: (raw.data ?? {}) as Record<string, unknown>,
      });
      return toWire(n);
    }
    case "get_notification": {
      const n = await store.getNotification(raw.id as NotId, recipientUsrId);
      return toWire(n);
    }
    case "mark_read": {
      const n = await store.markRead(raw.id as NotId, recipientUsrId);
      return toWire(n);
    }
    case "mark_unread": {
      const n = await store.markUnread(raw.id as NotId, recipientUsrId);
      return toWire(n);
    }
    case "dismiss": {
      const n = await store.dismiss(raw.id as NotId, recipientUsrId);
      return toWire(n);
    }
    default:
      throw new Error(`Unknown fixture op: ${op}`);
  }
}

// ─── Error class name resolver ───

function getErrorClassName(err: unknown): string {
  if (err instanceof Error) return err.constructor.name;
  return String(err);
}

// ─── Test runner ───

async function runTest(test: FixtureTest): Promise<void> {
  const store = new InMemoryNotifyStore();
  const vars: Record<string, unknown> = {};
  for (const name of test.users ?? []) vars[name] = generate("usr");

  for (const step of test.steps) {
    const input = resolveVars(step.input, vars) as Record<string, unknown>;

    if (step.expected?.error) {
      // Negative vector: expect a specific error class
      await expect(invokeOp(store, step.op, input, vars)).rejects.toSatisfy(
        (err: unknown) => getErrorClassName(err) === step.expected!.error!,
        `Expected ${step.expected.error} from op ${step.op}`,
      );
      continue;
    }

    const result = await invokeOp(store, step.op, input, vars);

    if (step.captures) {
      for (const [name, path] of Object.entries(step.captures)) {
        vars[name] = walkPath(result, path);
      }
    }

    if (step.expected?.result) {
      assertSubset(resolveVars(step.expected.result, vars), result, "result");
    }
  }

  expect(true).toBe(true);
}

// ─── Test factories ───

function loadFixture(name: string): FixtureFile {
  return JSON.parse(
    readFileSync(join(FIXTURES_DIR, name), "utf8"),
  ) as FixtureFile;
}

const lifecycleFixture = loadFixture("notifications/lifecycle-shape.json");
const recipientScopeFixture = loadFixture("notifications/recipient-scope.json");

describe(`Conformance · notifications.lifecycle [${lifecycleFixture.conformance_level}]`, () => {
  for (const t of lifecycleFixture.tests) {
    it(`[${t.id}] ${t.description}`, async () => {
      await runTest(t);
    });
  }
});

describe(`Conformance · notifications.recipient_scope [${recipientScopeFixture.conformance_level}]`, () => {
  for (const t of recipientScopeFixture.tests) {
    it(`[${t.id}] ${t.description}`, async () => {
      await runTest(t);
    });
  }
});

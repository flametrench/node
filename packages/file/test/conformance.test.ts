// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.4 conformance suite — Node / TypeScript harness for
// the file-metadata capability (ADR 0020).
//
// Fixture format: step-DSL with {varname} interpolation and captures.
// Result matching is SUPERSET (result ⊇ expected).
// Dates are serialized to ISO strings via toWire() before comparison.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { generate } from "@flametrench/ids";
import { describe, expect, it } from "vitest";

import {
  InMemoryFileMetadataStore,
  type Checksum,
  type CreateFileMetadataInput,
  type FileId,
  type OrgId,
  type UpdateFileMetadataInput,
  type UsrId,
} from "../src/index.js";
import type { FileMetadata } from "../src/types.js";

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

// ─── Wire serialization (FileMetadata → snake_case plain object) ───

function toWire(f: FileMetadata): Record<string, unknown> {
  return {
    id: f.id,
    scope: f.scope,
    owner_usr_id: f.ownerUsrId,
    name: f.name,
    content_type: f.contentType,
    size_bytes: f.sizeBytes,
    checksum: f.checksum,
    storage_ref: f.storageRef,
    status: f.status,
    created_at: f.createdAt.toISOString(),
    updated_at: f.updatedAt.toISOString(),
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
  store: InMemoryFileMetadataStore,
  op: string,
  raw: Record<string, unknown>,
): Promise<unknown> {
  switch (op) {
    case "create_file_metadata": {
      const f = await store.createFileMetadata({
        scope: raw.scope as OrgId,
        ownerUsrId: raw.owner_usr_id as UsrId,
        name: raw.name as string,
        contentType: raw.content_type as string,
        sizeBytes: raw.size_bytes as number | null,
        checksum: raw.checksum as Checksum | null,
        storageRef: raw.storage_ref as string | null,
        status: raw.status as CreateFileMetadataInput["status"],
      });
      return toWire(f);
    }
    case "get_file_metadata": {
      const f = await store.getFileMetadata(raw.id as FileId);
      return toWire(f);
    }
    case "update_file_metadata": {
      const f = await store.updateFileMetadata(raw.id as FileId, {
        name: raw.name as string | undefined,
        status: raw.status as UpdateFileMetadataInput["status"],
        sizeBytes: raw.size_bytes as number | null | undefined,
        checksum: raw.checksum as Checksum | null | undefined,
        storageRef: raw.storage_ref as string | null | undefined,
      });
      return toWire(f);
    }
    case "delete_file_metadata": {
      const f = await store.deleteFileMetadata(raw.id as FileId);
      return toWire(f);
    }
    default:
      throw new Error(`Unknown fixture op: ${op}`);
  }
}

// ─── Test runner ───

async function runTest(test: FixtureTest): Promise<void> {
  const fileStore = new InMemoryFileMetadataStore();
  const vars: Record<string, unknown> = {};
  for (const name of test.users ?? []) vars[name] = generate("usr");

  for (const step of test.steps) {
    const input = resolveVars(step.input, vars) as Record<string, unknown>;
    const result = await invokeOp(fileStore, step.op, input);

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

const fixture = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "file-metadata/lifecycle-shape.json"), "utf8"),
) as FixtureFile;

describe(`Conformance · file-metadata.lifecycle [${fixture.conformance_level}]`, () => {
  for (const t of fixture.tests) {
    it(`[${t.id}] ${t.description}`, async () => {
      await runTest(t);
    });
  }
});

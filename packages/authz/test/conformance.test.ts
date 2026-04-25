// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.1 conformance suite — Node / TypeScript harness
// for the authorization capability.
//
// Exercises check, check_any, and create_tuple (uniqueness + format)
// against the fixture corpus vendored from
// github.com/flametrench/spec/conformance/fixtures/authorization/.
// The fixtures under test/conformance/fixtures/ are a snapshot;
// the drift-check CI job verifies they match the upstream spec repo.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeEach, describe, expect, it } from "vitest";

import {
  DuplicateTupleError,
  EmptyRelationSetError,
  InMemoryTupleStore,
  InvalidFormatError,
  type SubjectType,
  type UsrId,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");

// ─── Wire-format → SDK adapter ───
//
// Fixtures use snake_case keys (subject_type, subject_id, relation,
// object_type, object_id) — the wire format. The Node SDK uses camelCase.
// These adapters translate.

interface WireTuple {
  subject_type: string;
  subject_id: string;
  relation: string;
  object_type: string;
  object_id: string;
}

interface WireCheck extends WireTuple {}

interface WireCheckSet {
  subject_type: string;
  subject_id: string;
  relations: string[];
  object_type: string;
  object_id: string;
}

function tupleFromWire(t: WireTuple) {
  return {
    subjectType: t.subject_type as SubjectType,
    subjectId: t.subject_id as UsrId,
    relation: t.relation,
    objectType: t.object_type,
    objectId: t.object_id,
  };
}

function checkSetFromWire(c: WireCheckSet) {
  return {
    subjectType: c.subject_type as SubjectType,
    subjectId: c.subject_id as UsrId,
    relations: c.relations,
    objectType: c.object_type,
    objectId: c.object_id,
  };
}

interface FixtureTest {
  id: string;
  description: string;
  input: Record<string, unknown>;
  expected: {
    result?: unknown;
    error?: string;
  };
}

interface FixtureFile {
  spec_version: string;
  capability: string;
  operation: string;
  conformance_level: "MUST" | "SHOULD" | "MAY";
  description: string;
  tests: FixtureTest[];
}

function loadFixture(relativePath: string): FixtureFile {
  const raw = readFileSync(join(FIXTURES_DIR, relativePath), "utf8");
  return JSON.parse(raw) as FixtureFile;
}

function errorCtorForSpecName(name: string) {
  switch (name) {
    case "DuplicateTupleError":
      return DuplicateTupleError;
    case "InvalidFormatError":
      return InvalidFormatError;
    case "EmptyRelationSetError":
      return EmptyRelationSetError;
    default:
      throw new Error(`Unknown spec error name: ${name}`);
  }
}

/** Seed an empty store with the fixture's `given_tuples` precondition. */
async function seed(store: InMemoryTupleStore, given: WireTuple[]): Promise<void> {
  for (const t of given) {
    await store.createTuple(tupleFromWire(t));
  }
}

// ─── authorization.check (exact match) ───

{
  const fixture = loadFixture("authorization/check.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}]`,
    () => {
      let store: InMemoryTupleStore;
      beforeEach(() => {
        store = new InMemoryTupleStore();
      });
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, async () => {
          const input = t.input as {
            given_tuples: WireTuple[];
            check: WireCheck;
          };
          await seed(store, input.given_tuples);
          const result = await store.check(tupleFromWire(input.check));
          const expected = t.expected.result as { allowed: boolean };
          expect(result.allowed).toBe(expected.allowed);
        });
      }
    },
  );
}

// ─── authorization.check_any (set form) ───

{
  const fixture = loadFixture("authorization/check-any.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}]`,
    () => {
      let store: InMemoryTupleStore;
      beforeEach(() => {
        store = new InMemoryTupleStore();
      });
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, async () => {
          const input = t.input as {
            given_tuples: WireTuple[];
            check: WireCheckSet;
          };
          await seed(store, input.given_tuples);
          if (t.expected.error) {
            const Ctor = errorCtorForSpecName(t.expected.error);
            await expect(
              store.checkAny(checkSetFromWire(input.check)),
            ).rejects.toThrow(Ctor);
          } else {
            const result = await store.checkAny(checkSetFromWire(input.check));
            const expected = t.expected.result as { allowed: boolean };
            expect(result.allowed).toBe(expected.allowed);
          }
        });
      }
    },
  );
}

// ─── authorization.create_tuple (uniqueness) ───

{
  const fixture = loadFixture("authorization/uniqueness.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · uniqueness`,
    () => {
      let store: InMemoryTupleStore;
      beforeEach(() => {
        store = new InMemoryTupleStore();
      });
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, async () => {
          const input = t.input as {
            given_tuples: WireTuple[];
            create: WireTuple;
          };
          await seed(store, input.given_tuples);
          if (t.expected.error) {
            const Ctor = errorCtorForSpecName(t.expected.error);
            await expect(
              store.createTuple(tupleFromWire(input.create)),
            ).rejects.toThrow(Ctor);
          } else {
            // The spec's expected.result for non-error create_tuple cases is
            // simply "ok" — meaning the tuple was created successfully.
            const created = await store.createTuple(tupleFromWire(input.create));
            expect(created.id).toMatch(/^tup_/);
          }
        });
      }
    },
  );
}

// ─── authorization.create_tuple (format) ───

{
  const fixture = loadFixture("authorization/format.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · format`,
    () => {
      let store: InMemoryTupleStore;
      beforeEach(() => {
        store = new InMemoryTupleStore();
      });
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, async () => {
          const input = t.input as {
            given_tuples: WireTuple[];
            create: WireTuple;
          };
          await seed(store, input.given_tuples);
          if (t.expected.error) {
            const Ctor = errorCtorForSpecName(t.expected.error);
            await expect(
              store.createTuple(tupleFromWire(input.create)),
            ).rejects.toThrow(Ctor);
          } else {
            const created = await store.createTuple(tupleFromWire(input.create));
            expect(created.id).toMatch(/^tup_/);
          }
        });
      }
    },
  );
}

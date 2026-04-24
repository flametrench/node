// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.1 conformance suite — Node / TypeScript harness.
//
// Exercises the IDs capability against the fixture corpus vendored from
// github.com/flametrench/spec/conformance/fixtures/ids/. The fixtures
// under test/conformance/fixtures/ are a snapshot; the drift-check CI
// job verifies they match the upstream spec repo.
//
// Every test name is "[{fixture_id}] {description}" so failures point
// directly at a spec-linked fixture. Do not modify test behavior here;
// if a fixture needs to change, change it in the spec repo and re-vendor.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  decode,
  encode,
  InvalidIdError,
  InvalidTypeError,
  isValid,
  typeOf,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");

interface FixtureTest {
  id: string;
  description: string;
  input: Record<string, unknown>;
  expected: {
    result?: unknown;
    error?: "InvalidIdError" | "InvalidTypeError";
    error_matches?: string;
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
    case "InvalidIdError":
      return InvalidIdError;
    case "InvalidTypeError":
      return InvalidTypeError;
    default:
      throw new Error(`Unknown spec error name: ${name}`);
  }
}

// ─── ids.encode ───

{
  const fixture = loadFixture("ids/encode.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}]`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as { type: string; uuid: string };
          if (t.expected.error) {
            const Ctor = errorCtorForSpecName(t.expected.error);
            expect(() => encode(input.type, input.uuid)).toThrow(Ctor);
          } else {
            expect(encode(input.type, input.uuid)).toBe(t.expected.result);
          }
        });
      }
    },
  );
}

// ─── ids.decode (positive + round-trip) ───

{
  const fixture = loadFixture("ids/decode.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · positive`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as { id: string };
          expect(decode(input.id)).toEqual(t.expected.result);
        });
      }
    },
  );
}

// ─── ids.decode (rejection) ───

{
  const fixture = loadFixture("ids/decode-reject.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · rejection`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as { id: string };
          const Ctor = errorCtorForSpecName(t.expected.error!);
          expect(() => decode(input.id)).toThrow(Ctor);
        });
      }
    },
  );
}

// ─── ids.is_valid ───

{
  const fixture = loadFixture("ids/is-valid.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}]`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as { id: string; expected_type?: string };
          // `expected_type` is passed only when the fixture declares it.
          const result =
            input.expected_type !== undefined
              ? isValid(input.id, input.expected_type as never)
              : isValid(input.id);
          expect(result).toBe(t.expected.result);
        });
      }
    },
  );
}

// ─── ids.type_of ───

{
  const fixture = loadFixture("ids/type-of.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}]`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as { id: string };
          if (t.expected.error) {
            const Ctor = errorCtorForSpecName(t.expected.error);
            expect(() => typeOf(input.id)).toThrow(Ctor);
          } else {
            expect(typeOf(input.id)).toBe(t.expected.result);
          }
        });
      }
    },
  );
}

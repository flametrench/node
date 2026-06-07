// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.4 conformance suite — Node / TypeScript harness for
// the flags.assign_bucket capability (ADR 0021 §Deterministic bucketing).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { assignBucket } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");

interface BucketFixtureTest {
  id: string;
  description: string;
  input: { key: string; subject_id: string };
  expected: { result: number };
}

interface BucketFixtureFile {
  spec_version: string;
  capability: string;
  conformance_level: string;
  tests: BucketFixtureTest[];
}

const fixture = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "flags/assign-bucket.json"), "utf8"),
) as BucketFixtureFile;

describe(`Conformance · flags.assign_bucket [${fixture.conformance_level}]`, () => {
  for (const t of fixture.tests) {
    it(`[${t.id}] ${t.description}`, () => {
      const result = assignBucket(t.input.key, t.input.subject_id);
      expect(result).toBe(t.expected.result);
    });
  }
});

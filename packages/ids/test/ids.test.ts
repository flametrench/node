// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// SDK-specific tests for @flametrench/ids.
//
// This file intentionally covers ONLY behaviors that the language-agnostic
// conformance suite (test/conformance.test.ts) cannot express — TypeScript
// type guards and stateful operations (generate uniqueness and time-
// ordering). Every input/output pair and every rejection case that CAN be
// expressed as fixture data lives in the conformance suite, where it is
// verified identically in every Flametrench SDK.
//
// When adding a new spec-defined behavior, first ask: can it be expressed
// as fixture JSON? If yes, add it to spec/conformance/fixtures/ids/ and
// re-vendor — not here.

import { describe, expect, it } from "vitest";

import {
  generate,
  InvalidTypeError,
  isId,
  isValid,
  TYPES,
} from "../src/index.js";

const REGISTERED_TYPES = Object.keys(TYPES) as (keyof typeof TYPES)[];
const SAMPLE_HEX = "0190f2a81b3c7abc8123456789abcdef";

describe("generate() — stateful, not expressible as a fixture", () => {
  it.each(REGISTERED_TYPES)(
    "produces a valid ID of the requested type (%s)",
    (type) => {
      const id = generate(type);
      expect(isValid(id, type)).toBe(true);
    },
  );

  it("produces sortable IDs (UUIDv7 time ordering)", async () => {
    const first = generate("usr");
    await new Promise((resolve) => setTimeout(resolve, 2));
    const second = generate("usr");

    expect(first.localeCompare(second)).toBeLessThan(0);
  });

  it("produces unique IDs", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => generate("usr")));
    expect(ids.size).toBe(1000);
  });

  it("rejects unregistered type prefixes", () => {
    expect(() => generate("xyz" as never)).toThrow(InvalidTypeError);
  });
});

describe("isId() — TypeScript type guard", () => {
  it("narrows unknown values to string when valid", () => {
    const value: unknown = `usr_${SAMPLE_HEX}`;

    if (isId(value, "usr")) {
      // Compiler proof: value is narrowed to string here.
      expect(value.startsWith("usr_")).toBe(true);
    } else {
      throw new Error("expected value to be recognized as a user ID");
    }
  });

  it("returns false for non-string inputs", () => {
    expect(isId(123)).toBe(false);
    expect(isId(null)).toBe(false);
    expect(isId(undefined)).toBe(false);
    expect(isId({})).toBe(false);
  });
});

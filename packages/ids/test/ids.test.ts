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
  decodeAny,
  generate,
  InvalidIdError,
  InvalidTypeError,
  isId,
  isValid,
  isValidShape,
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

describe("decodeAny() — adapter helper for application-defined types", () => {
  it("decodes a registered Flametrench prefix the same as decode()", () => {
    const result = decodeAny(`usr_${SAMPLE_HEX}`);
    expect(result.type).toBe("usr");
    expect(result.uuid).toBe("0190f2a8-1b3c-7abc-8123-456789abcdef");
  });

  it("decodes an application-defined prefix that decode() would reject", () => {
    // 'proj' is not in TYPES — strict decode throws InvalidTypeError;
    // decodeAny accepts it.
    expect(() =>
      decodeAny(`xyz_${SAMPLE_HEX}`),
    ).not.toThrow();
    const result = decodeAny(`proj_${SAMPLE_HEX}`);
    expect(result.type).toBe("proj");
  });

  it("rejects malformed shape with InvalidIdError, never InvalidTypeError", () => {
    expect(() => decodeAny("no-separator")).toThrow(InvalidIdError);
    expect(() => decodeAny(`usr_${SAMPLE_HEX.toUpperCase()}`)).toThrow(
      InvalidIdError,
    );
    expect(() => decodeAny("_0190f2a81b3c7abc8123456789abcdef")).toThrow(
      InvalidIdError,
    );
    expect(() =>
      decodeAny("usr_00000000000000000000000000000000"),
    ).toThrow(InvalidIdError);
  });
});

describe("isValidShape() — predicate counterpart to decodeAny", () => {
  it("returns true for application-defined prefixes", () => {
    expect(isValidShape(`proj_${SAMPLE_HEX}`)).toBe(true);
    expect(isValidShape(`doc_${SAMPLE_HEX}`)).toBe(true);
  });

  it("returns true for registered prefixes", () => {
    expect(isValidShape(`usr_${SAMPLE_HEX}`)).toBe(true);
  });

  it("returns false for malformed shape", () => {
    expect(isValidShape("not an id")).toBe(false);
    expect(isValidShape(`usr_${SAMPLE_HEX.toUpperCase()}`)).toBe(false);
    expect(isValidShape("usr_ffffffffffffffffffffffffffffffff")).toBe(false);
  });
});

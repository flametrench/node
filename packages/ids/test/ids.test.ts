// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  decode,
  encode,
  generate,
  InvalidIdError,
  InvalidTypeError,
  isId,
  isValid,
  TYPES,
  typeOf,
} from "../src/index.js";

const SAMPLE_UUID = "0190f2a8-1b3c-7abc-8123-456789abcdef";
const SAMPLE_HEX = "0190f2a81b3c7abc8123456789abcdef";
const REGISTERED_TYPES = Object.keys(TYPES) as (keyof typeof TYPES)[];

describe("encode()", () => {
  it("encodes a canonical UUID string into wire format", () => {
    expect(encode("usr", SAMPLE_UUID)).toBe(`usr_${SAMPLE_HEX}`);
  });

  it("normalizes uppercase UUIDs to lowercase hex", () => {
    const upper = SAMPLE_UUID.toUpperCase();
    expect(encode("usr", upper)).toBe(`usr_${SAMPLE_HEX}`);
  });

  it("rejects unregistered type prefixes", () => {
    expect(() => encode("xyz", SAMPLE_UUID)).toThrow(InvalidTypeError);
  });

  it("rejects malformed UUID strings", () => {
    expect(() => encode("usr", "not-a-uuid")).toThrow(InvalidIdError);
  });

  it.each(REGISTERED_TYPES)(
    "produces IDs of expected length for type %s",
    (type) => {
      const id = encode(type, SAMPLE_UUID);
      expect(id.length).toBe(type.length + 1 + 32);
    },
  );
});

describe("decode()", () => {
  it("decodes a wire-format ID into type and canonical UUID", () => {
    expect(decode(`usr_${SAMPLE_HEX}`)).toEqual({
      type: "usr",
      uuid: SAMPLE_UUID,
    });
  });

  it.each(REGISTERED_TYPES)("is the inverse of encode for type %s", (type) => {
    const encoded = encode(type, SAMPLE_UUID);
    const decoded = decode(encoded);

    expect(decoded.type).toBe(type);
    expect(decoded.uuid).toBe(SAMPLE_UUID);
  });

  it("rejects IDs without a type separator", () => {
    expect(() => decode(`usr${SAMPLE_HEX}`)).toThrow(InvalidIdError);
    expect(() => decode(`usr${SAMPLE_HEX}`)).toThrow(/missing type separator/);
  });

  it("rejects unregistered type prefixes", () => {
    expect(() => decode(`xyz_${SAMPLE_HEX}`)).toThrow(InvalidTypeError);
  });

  it.each([
    ["too short", "usr_0190f2a8"],
    ["too long", `usr_${SAMPLE_HEX}0000`],
    ["non-hex", "usr_0190f2a81b3c7abc8123456789abcdeg0"],
    ["empty payload", "usr_"],
    ["uppercase hex", `usr_${SAMPLE_HEX.toUpperCase()}`],
  ])("rejects %s payloads", (_label, malformed) => {
    expect(() => decode(malformed)).toThrow(InvalidIdError);
  });

  it("rejects payloads that parse to invalid UUIDs", () => {
    expect(() => decode("usr_ffffffffffffffffffffffffffffffff")).toThrow(
      InvalidIdError,
    );
  });
});

describe("isValid()", () => {
  it("returns true for well-formed IDs", () => {
    expect(isValid(`usr_${SAMPLE_HEX}`)).toBe(true);
  });

  it.each([
    ["no separator", `usr${SAMPLE_HEX}`],
    ["unknown type", `xyz_${SAMPLE_HEX}`],
    ["short payload", "usr_deadbeef"],
    ["empty string", ""],
    ["garbage", "not an id at all"],
  ])("returns false for %s", (_label, malformed) => {
    expect(isValid(malformed)).toBe(false);
  });

  it("validates against an expected type when provided", () => {
    const id = `usr_${SAMPLE_HEX}`;
    expect(isValid(id, "usr")).toBe(true);
    expect(isValid(id, "org")).toBe(false);
  });
});

describe("typeOf()", () => {
  it("returns the type prefix of a valid ID", () => {
    expect(typeOf(`org_${SAMPLE_HEX}`)).toBe("org");
  });

  it("throws on invalid IDs", () => {
    expect(() => typeOf("garbage")).toThrow(InvalidIdError);
  });
});

describe("generate()", () => {
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
    const ids = new Set(
      Array.from({ length: 1000 }, () => generate("usr")),
    );
    expect(ids.size).toBe(1000);
  });
});

describe("isId()", () => {
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

describe("round-trip properties", () => {
  const corpus = [
    SAMPLE_UUID,
    "01000000-0000-7000-8000-000000000000",
    "01ffffff-ffff-7fff-bfff-ffffffffffff",
  ];

  it.each(REGISTERED_TYPES)(
    "encode then decode recovers the original UUID for type %s",
    (type) => {
      for (const original of corpus) {
        const encoded = encode(type, original);
        const decoded = decode(encoded);

        expect(decoded.uuid).toBe(original);
        expect(decoded.type).toBe(type);
      }
    },
  );
});

describe("cross-language parity", () => {
  it("produces wire-format strings identical to the Laravel SDK's Id::encode", () => {
    // These fixtures must match flametrench/ids (PHP) exactly.
    // Conformance is enforced at the specification level; both SDKs must
    // agree on the byte-level representation of every encoded ID.
    const fixtures = [
      {
        type: "usr",
        uuid: "0190f2a8-1b3c-7abc-8123-456789abcdef",
        wire: "usr_0190f2a81b3c7abc8123456789abcdef",
      },
      {
        type: "org",
        uuid: "01000000-0000-7000-8000-000000000000",
        wire: "org_01000000000070008000000000000000",
      },
      {
        type: "ses",
        uuid: "01ffffff-ffff-7fff-bfff-ffffffffffff",
        wire: "ses_01ffffffffff7fffbfffffffffffffff",
      },
    ];

    for (const { type, uuid, wire } of fixtures) {
      expect(encode(type, uuid)).toBe(wire);
      expect(decode(wire)).toEqual({ type, uuid });
    }
  });
});

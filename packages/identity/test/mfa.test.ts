// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Unit tests for v0.2 MFA primitives in the Node SDK.
// Mirrors identity-python/tests/test_mfa.py exactly so any
// behavioral drift between Python and Node surfaces as a failing test.

import { describe, expect, it } from "vitest";

import {
  DEFAULT_TOTP_PERIOD,
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_LENGTH,
  generateRecoveryCode,
  generateRecoveryCodes,
  generateTotpSecret,
  isMfaPolicyActiveNow,
  isValidRecoveryCode,
  normalizeRecoveryInput,
  totpCompute,
  totpOtpauthUri,
  totpVerify,
  type UserMfaPolicy,
} from "../src/index.js";

const SECRET_SHA1 = new TextEncoder().encode("12345678901234567890");
const SECRET_SHA256 = new TextEncoder().encode(
  "12345678901234567890123456789012",
);
const SECRET_SHA512 = new TextEncoder().encode(
  "1234567890123456789012345678901234567890123456789012345678901234",
);

// ─── TOTP RFC 6238 §B vectors ───

describe("TOTP RFC 6238 §B vectors — SHA-1", () => {
  for (const [timestamp, expected] of [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
    [20000000000, "65353130"],
  ] as const) {
    it(`t=${timestamp} → ${expected}`, () => {
      expect(
        totpCompute(SECRET_SHA1, timestamp, { digits: 8, algorithm: "sha1" }),
      ).toBe(expected);
    });
  }
});

describe("TOTP RFC 6238 §B vectors — SHA-256", () => {
  for (const [timestamp, expected] of [
    [59, "46119246"],
    [1111111109, "68084774"],
    [1111111111, "67062674"],
    [1234567890, "91819424"],
    [2000000000, "90698825"],
    [20000000000, "77737706"],
  ] as const) {
    it(`t=${timestamp} → ${expected}`, () => {
      expect(
        totpCompute(SECRET_SHA256, timestamp, {
          digits: 8,
          algorithm: "sha256",
        }),
      ).toBe(expected);
    });
  }
});

describe("TOTP RFC 6238 §B vectors — SHA-512", () => {
  for (const [timestamp, expected] of [
    [59, "90693936"],
    [1111111109, "25091201"],
    [1111111111, "99943326"],
    [1234567890, "93441116"],
    [2000000000, "38618901"],
    [20000000000, "47863826"],
  ] as const) {
    it(`t=${timestamp} → ${expected}`, () => {
      expect(
        totpCompute(SECRET_SHA512, timestamp, {
          digits: 8,
          algorithm: "sha512",
        }),
      ).toBe(expected);
    });
  }
});

// ─── totpVerify ───

describe("totpVerify", () => {
  const ts = 1234567890;

  it("verifies the current window", () => {
    const code = totpCompute(SECRET_SHA1, ts);
    expect(totpVerify(SECRET_SHA1, code, { timestamp: ts })).toBe(true);
  });

  it("verifies one window earlier (drift=-1)", () => {
    const prev = totpCompute(SECRET_SHA1, ts - DEFAULT_TOTP_PERIOD);
    expect(totpVerify(SECRET_SHA1, prev, { timestamp: ts })).toBe(true);
  });

  it("verifies one window later (drift=+1)", () => {
    const next = totpCompute(SECRET_SHA1, ts + DEFAULT_TOTP_PERIOD);
    expect(totpVerify(SECRET_SHA1, next, { timestamp: ts })).toBe(true);
  });

  it("rejects two windows earlier with default drift", () => {
    const old = totpCompute(SECRET_SHA1, ts - 2 * DEFAULT_TOTP_PERIOD);
    expect(totpVerify(SECRET_SHA1, old, { timestamp: ts })).toBe(false);
  });

  it("rejects garbage input", () => {
    expect(totpVerify(SECRET_SHA1, "abc", { timestamp: ts })).toBe(false);
    expect(totpVerify(SECRET_SHA1, "", { timestamp: ts })).toBe(false);
    expect(totpVerify(SECRET_SHA1, "12345", { timestamp: ts })).toBe(false);
  });

  it("rejects wrong code", () => {
    expect(totpVerify(SECRET_SHA1, "000000", { timestamp: ts })).toBe(false);
  });
});

// ─── secret generation ───

describe("generateTotpSecret", () => {
  it("default length is 20 bytes", () => {
    expect(generateTotpSecret().length).toBe(20);
  });

  it("produces unique secrets", () => {
    const set = new Set<string>();
    for (let i = 0; i < 50; i++) {
      set.add(Buffer.from(generateTotpSecret()).toString("hex"));
    }
    expect(set.size).toBe(50);
  });
});

// ─── otpauth URI ───

describe("totpOtpauthUri", () => {
  it("contains secret, label, and issuer", () => {
    const uri = totpOtpauthUri({
      secret: SECRET_SHA1,
      label: "alice@example.com",
      issuer: "Flametrench",
    });
    expect(uri.startsWith("otpauth://totp/")).toBe(true);
    expect(uri).toContain("Flametrench");
    expect(uri).toContain("alice%40example.com");
    expect(uri).toContain("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  });
});

// ─── recovery codes ───

describe("recovery code format", () => {
  it("one code matches XXXX-XXXX-XXXX", () => {
    const code = generateRecoveryCode();
    expect(code.length).toBe(RECOVERY_CODE_LENGTH + 2);
    const parts = code.split("-");
    expect(parts.length).toBe(3);
    for (const part of parts) {
      expect(part.length).toBe(4);
    }
  });

  it("excludes ambiguous characters", () => {
    const code = generateRecoveryCode();
    for (const ch of "01OIL") {
      expect(code).not.toContain(ch);
    }
  });

  it("uses only uppercase / digits", () => {
    const code = generateRecoveryCode();
    for (const ch of code.replace(/-/g, "")) {
      expect(ch === ch.toUpperCase()).toBe(true);
    }
  });

  it("set has 10 codes", () => {
    expect(generateRecoveryCodes().length).toBe(RECOVERY_CODE_COUNT);
  });

  it("set codes are unique", () => {
    const codes = generateRecoveryCodes();
    expect(new Set(codes).size).toBe(RECOVERY_CODE_COUNT);
  });

  it("normalizeRecoveryInput uppercases and strips whitespace", () => {
    expect(normalizeRecoveryInput("  abcd-efgh-jkmn  ")).toBe(
      "ABCD-EFGH-JKMN",
    );
  });

  it("normalizeRecoveryInput preserves hyphens", () => {
    expect(normalizeRecoveryInput("abcd-efgh-jkmn")).toBe("ABCD-EFGH-JKMN");
  });
});

// ─── isMfaPolicyActiveNow ───

describe("isMfaPolicyActiveNow", () => {
  const now = new Date("2026-04-25T12:00:00Z");

  it("required + no grace → active", () => {
    const p: UserMfaPolicy = {
      usrId: "usr_x",
      required: true,
      graceUntil: null,
      updatedAt: now,
    };
    expect(isMfaPolicyActiveNow(p, now)).toBe(true);
  });

  it("required + future grace → inactive", () => {
    const p: UserMfaPolicy = {
      usrId: "usr_x",
      required: true,
      graceUntil: new Date("2026-05-01T00:00:00Z"),
      updatedAt: now,
    };
    expect(isMfaPolicyActiveNow(p, now)).toBe(false);
  });

  it("required + past grace → active", () => {
    const p: UserMfaPolicy = {
      usrId: "usr_x",
      required: true,
      graceUntil: new Date("2026-04-01T00:00:00Z"),
      updatedAt: now,
    };
    expect(isMfaPolicyActiveNow(p, now)).toBe(true);
  });

  it("not required → inactive", () => {
    const p: UserMfaPolicy = {
      usrId: "usr_x",
      required: false,
      graceUntil: null,
      updatedAt: now,
    };
    expect(isMfaPolicyActiveNow(p, now)).toBe(false);
  });
});

// Direct format-predicate exercise (otherwise only conformance covers it).
describe("isValidRecoveryCode", () => {
  it("accepts canonical form", () => {
    expect(isValidRecoveryCode("ABCD-EFGH-JKMN")).toBe(true);
  });

  it("rejects ambiguous characters", () => {
    expect(isValidRecoveryCode("ABCD-EFGH-JKM0")).toBe(false);
    expect(isValidRecoveryCode("ABCD-EFGH-JKMO")).toBe(false);
    expect(isValidRecoveryCode("ABCD-EFGH-JK1N")).toBe(false);
    expect(isValidRecoveryCode("ABCD-EFGH-JKMI")).toBe(false);
    expect(isValidRecoveryCode("ABCD-EFGH-JKML")).toBe(false);
  });

  it("rejects malformed shape", () => {
    expect(isValidRecoveryCode("abcd-efgh-jkmn")).toBe(false);
    expect(isValidRecoveryCode("ABCDEFGHJKMN")).toBe(false);
    expect(isValidRecoveryCode("ABCD-EFGH")).toBe(false);
  });
});

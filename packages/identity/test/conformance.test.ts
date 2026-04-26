// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.1 conformance suite — Node / TypeScript harness
// for the identity capability.
//
// Exercises verify_password against the cross-language Argon2id parity
// fixture vendored from
// github.com/flametrench/spec/conformance/fixtures/identity/.
// The fixtures under test/conformance/fixtures/ are a snapshot;
// the drift-check CI job verifies they match the upstream spec repo.
//
// Why this fixture matters: the same PHC-encoded Argon2id hash MUST
// verify identically across Node, PHP, Python, and Java SDKs. If this
// breaks, password-based auth becomes non-portable — which would defeat
// Flametrench's interop goal.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  isValidRecoveryCode,
  totpCompute,
  verifyPasswordHash,
  WebAuthnError,
  webauthnVerifyAssertion,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");

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
  shared?: Record<string, unknown>;
}

function loadFixture(relativePath: string): FixtureFile {
  const raw = readFileSync(join(FIXTURES_DIR, relativePath), "utf8");
  return JSON.parse(raw) as FixtureFile;
}

// ─── identity.verify_password ───

{
  const fixture = loadFixture("identity/argon2id.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}]`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, async () => {
          const input = t.input as {
            phc_hash: string;
            candidate_password: string;
          };
          const result = await verifyPasswordHash(
            input.phc_hash,
            input.candidate_password,
          );
          expect(result).toBe(t.expected.result);
        });
      }
    },
  );
}

// ─── v0.2: identity.totp_compute (RFC 6238) ───

{
  const fixture = loadFixture("identity/mfa/totp-rfc6238.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · RFC 6238`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as {
            secret_ascii: string;
            timestamp: number;
            digits: number;
            algorithm: "sha1" | "sha256" | "sha512";
          };
          const secret = new TextEncoder().encode(input.secret_ascii);
          const result = totpCompute(secret, input.timestamp, {
            digits: input.digits,
            algorithm: input.algorithm,
          });
          expect(result).toBe(t.expected.result);
        });
      }
    },
  );
}

// ─── v0.2: identity.generate_recovery_code (format predicate) ───

{
  const fixture = loadFixture("identity/mfa/recovery-code-format.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · format`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as { code: string };
          expect(isValidRecoveryCode(input.code)).toBe(t.expected.result);
        });
      }
    },
  );
}

// ─── v0.2: identity.webauthn_verify_assertion ───

interface WebAuthnFixtureInput {
  cose_public_key_hex?: string;
  stored_sign_count?: number;
  stored_rp_id?: string;
  expected_challenge_hex?: string;
  expected_origin?: string;
  authenticator_data_hex?: string;
  client_data_json_hex?: string;
  signature_hex?: string;
  require_user_verified?: boolean;
  require_user_present?: boolean;
}

function runWebauthn(
  shared: WebAuthnFixtureInput,
  test: FixtureTest,
): { ok: boolean; new_sign_count?: number; reason?: string } {
  const inp: WebAuthnFixtureInput = {
    ...shared,
    ...(test.input as WebAuthnFixtureInput),
  };
  try {
    const result = webauthnVerifyAssertion({
      cosePublicKey: Buffer.from(inp.cose_public_key_hex!, "hex"),
      storedSignCount: inp.stored_sign_count!,
      storedRpId: inp.stored_rp_id!,
      expectedChallenge: Buffer.from(inp.expected_challenge_hex!, "hex"),
      expectedOrigin: inp.expected_origin!,
      authenticatorData: Buffer.from(inp.authenticator_data_hex!, "hex"),
      clientDataJson: Buffer.from(inp.client_data_json_hex!, "hex"),
      signature: Buffer.from(inp.signature_hex!, "hex"),
      requireUserVerified: inp.require_user_verified ?? true,
      requireUserPresent: inp.require_user_present ?? true,
    });
    return { ok: true, new_sign_count: result.newSignCount };
  } catch (err) {
    if (err instanceof WebAuthnError) {
      return { ok: false, reason: err.reason };
    }
    throw err;
  }
}

for (const path of [
  "identity/mfa/webauthn-assertion.json",
  "identity/mfa/webauthn-counter-decrease-rejected.json",
  "identity/mfa/webauthn-assertion-algorithms.json",
]) {
  const fixture = loadFixture(path);
  const shared = (fixture.shared ?? {}) as WebAuthnFixtureInput;
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · ${path.split("/").pop()}`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const actual = runWebauthn(shared, t);
          expect(actual).toEqual(t.expected.result);
        });
      }
    },
  );
}

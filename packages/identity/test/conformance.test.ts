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
  AlreadyTerminalError,
  classifyBearer,
  InMemoryIdentityStore,
  isStructurallyValidPatToken,
  isValidRecoveryCode,
  NotFoundError,
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

// ─── v0.3: identity.verify_pat_token — wire-format structural validation ───

{
  const fixture = loadFixture("identity/pat/token-format.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · token-format`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as { token: string };
          expect(isStructurallyValidPatToken(input.token)).toBe(t.expected.result);
        });
      }
    },
  );
}

// ─── v0.3: identity.resolve_bearer — bearer prefix dispatch ───

{
  const fixture = loadFixture("identity/pat/bearer-prefix-routing.json");
  describe(
    `Conformance · ${fixture.capability}.${fixture.operation} [${fixture.conformance_level}] · bearer-prefix-routing`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, () => {
          const input = t.input as { token: string };
          expect(classifyBearer(input.token)).toBe(t.expected.result);
        });
      }
    },
  );
}

// ─── Step-DSL runner (v0.2: list_users, update_user / display_name) ───
//
// Fixtures using the `steps` format are stateful: each test gets its own fresh
// InMemoryIdentityStore. Steps may capture values from prior results and
// reference them as `{varname}` interpolations in subsequent inputs.

interface StepExpected {
  data_ids_in_order?: string[];
  data_ids_unordered?: string[];
  next_cursor?: string | null;
  user_display_names?: Record<string, string | null>;
  error?: string;
}

interface Step {
  op: string;
  input?: Record<string, unknown>;
  captures?: Record<string, string>;
  expected?: StepExpected;
}

interface StatefulFixtureTest {
  id: string;
  description: string;
  steps: Step[];
}

interface StatefulFixtureFile {
  spec_version: string;
  capability: string;
  operation: string;
  conformance_level: "MUST" | "SHOULD" | "MAY";
  description: string;
  tests: StatefulFixtureTest[];
}

function loadStatefulFixture(relativePath: string): StatefulFixtureFile {
  const raw = readFileSync(join(FIXTURES_DIR, relativePath), "utf8");
  return JSON.parse(raw) as StatefulFixtureFile;
}

function snakeToCamel(s: string): string {
  return s.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

function resolveCapturePath(
  obj: Record<string, unknown>,
  path: string,
): string | null {
  const parts = path.split(".");
  let cur: unknown = obj;
  for (const part of parts) {
    if (cur == null || typeof cur !== "object") return null;
    const camelKey = snakeToCamel(part);
    cur = (cur as Record<string, unknown>)[camelKey];
  }
  return cur == null ? null : String(cur);
}

function interpolateInput(
  inp: Record<string, unknown>,
  captures: Map<string, string>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(inp).map(([k, v]) => [
      k,
      typeof v === "string"
        ? v.replace(/\{(\w+)\}/g, (_, name: string) => captures.get(name) ?? `{${name}}`)
        : v,
    ]),
  );
}

async function runStepDslFixture(
  fixture: StatefulFixtureFile,
): Promise<void> {
  const { capability, operation, conformance_level } = fixture;
  describe(
    `Conformance · ${capability}.${operation} [${conformance_level}]`,
    () => {
      for (const t of fixture.tests) {
        it(`[${t.id}] ${t.description}`, async () => {
          const store = new InMemoryIdentityStore();
          const captures = new Map<string, string>();

          for (const step of t.steps) {
            const raw = step.input ?? {};
            const inp = interpolateInput(raw, captures);
            const expectedError = step.expected?.error;

            type StepResult = Record<string, unknown>;
            let stepResult: StepResult | null = null;

            const attempt = async (): Promise<StepResult> => {
              switch (step.op) {
                case "create_user": {
                  const user = await store.createUser({
                    displayName: inp.display_name as string | null | undefined,
                  });
                  return { user };
                }

                case "create_user_with_password_credential": {
                  const user = await store.createUser({});
                  const credential = await store.createCredential({
                    type: "password",
                    usrId: user.id,
                    identifier: inp.identifier as string,
                    password: inp.password as string,
                  });
                  return { user, credential };
                }

                case "suspend_user": {
                  const user = await store.suspendUser(inp.usr_id as `usr_${string}`);
                  return { user };
                }

                case "revoke_user": {
                  const user = await store.revokeUser(inp.usr_id as `usr_${string}`);
                  return { user };
                }

                case "revoke_credential": {
                  const credential = await store.revokeCredential(
                    inp.cred_id as `cred_${string}`,
                  );
                  return { credential };
                }

                case "update_user": {
                  const updateInput: { usrId: `usr_${string}`; displayName?: string | null } = {
                    usrId: inp.usr_id as `usr_${string}`,
                  };
                  if ("display_name" in inp) {
                    updateInput.displayName = inp.display_name as string | null;
                  }
                  const user = await store.updateUser(updateInput);
                  return { user };
                }

                case "assert_user_fields": {
                  const user = await store.getUser(inp.usr_id as `usr_${string}`);
                  expect(user.displayName).toBe(inp.expected_display_name ?? null);
                  return { user };
                }

                case "list_users": {
                  const opts: Record<string, unknown> = {};
                  if (inp.status !== undefined) opts.status = inp.status;
                  if (inp.query !== undefined) opts.query = inp.query;
                  if (inp.limit !== undefined) opts.limit = inp.limit;
                  if (inp.cursor !== undefined) opts.cursor = inp.cursor;
                  const page = await store.listUsers(
                    opts as Parameters<typeof store.listUsers>[0],
                  );
                  return { page };
                }

                default:
                  throw new Error(`Unknown step op: ${step.op}`);
              }
            };

            try {
              stepResult = await attempt();
            } catch (err) {
              if (expectedError) {
                expect((err as Error).name).toBe(expectedError);
                continue;
              }
              throw err;
            }

            if (expectedError) {
              throw new Error(
                `Step '${step.op}' expected error '${expectedError}' but succeeded`,
              );
            }

            // Capture values from result
            if (step.captures) {
              for (const [captureKey, capturePath] of Object.entries(
                step.captures,
              )) {
                const captured = resolveCapturePath(stepResult, capturePath);
                if (captured !== null) {
                  captures.set(captureKey, captured);
                }
              }
            }

            // Assertions on step result
            const expected = step.expected;
            if (!expected) continue;

            if (expected.data_ids_in_order !== undefined) {
              const page = stepResult.page as { data: Array<{ id: string }> };
              const actualIds = page.data.map((u) => u.id);
              const expectedIds = expected.data_ids_in_order.map((raw) =>
                raw.replace(/\{(\w+)\}/g, (_, name: string) => captures.get(name) ?? `{${name}}`),
              );
              expect(actualIds).toEqual(expectedIds);
            }

            if (expected.data_ids_unordered !== undefined) {
              const page = stepResult.page as { data: Array<{ id: string }> };
              const actualIds = page.data.map((u) => u.id).sort();
              const expectedIds = expected.data_ids_unordered
                .map((raw) =>
                  raw.replace(/\{(\w+)\}/g, (_, name: string) => captures.get(name) ?? `{${name}}`),
                )
                .sort();
              expect(actualIds).toEqual(expectedIds);
            }

            if ("next_cursor" in expected) {
              const page = stepResult.page as { nextCursor: string | null };
              expect(page.nextCursor).toBe(expected.next_cursor ?? null);
            }

            if (expected.user_display_names !== undefined) {
              const page = stepResult.page as {
                data: Array<{ id: string; displayName: string | null }>;
              };
              for (const [rawId, expectedName] of Object.entries(
                expected.user_display_names,
              )) {
                const resolvedId = rawId.replace(
                  /\{(\w+)\}/g,
                  (_, name: string) => captures.get(name) ?? `{${name}}`,
                );
                const found = page.data.find((u) => u.id === resolvedId);
                expect(found, `user ${resolvedId} not in page`).toBeDefined();
                expect(found!.displayName).toBe(expectedName);
              }
            }
          }
        });
      }
    },
  );
}

// ─── v0.2: identity.list_users ───

{
  const fixture = loadStatefulFixture("identity/list-users.json");
  await runStepDslFixture(fixture);
}

// ─── v0.2: identity.update_user / display_name ───

{
  const fixture = loadStatefulFixture("identity/user-display-name.json");
  await runStepDslFixture(fixture);
}

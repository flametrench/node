// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Personal access token primitive (ADR 0016 — v0.3).
 *
 * PATs are long-lived bearer credentials bound to a `usr_id`, intended
 * for non-interactive use (CLI, CI, server-to-server). They are NOT a
 * cred variant: different lifecycle (no rotation, no `replaces` chain),
 * different verification path (the secret IS the proof; no challenge),
 * different audit shape (`auth.kind = 'pat'`).
 *
 * Wire format: `pat_<32hex-id>_<base64url-secret>`. The plaintext token
 * leaves the server exactly once, in {@link CreatePatResult}; the
 * server stores only an Argon2id hash of the secret segment at the
 * cred-password parameter floor.
 */

import type { UsrId } from "./types.js";

/** Wire-format prefix-routed PAT id. */
export type PatId = `pat_${string}`;

/**
 * Lifecycle status of a PAT. Active → present, not expired, not revoked.
 * Expired → past `expiresAt`. Revoked → `revokePat` called. The latter
 * two are terminal: a PAT cannot return to active.
 */
export type PatStatus = "active" | "expired" | "revoked";

/**
 * Server-persisted personal access token record. The secret hash is
 * NEVER carried on this object — only metadata. To obtain the
 * plaintext token, call {@link IdentityStore.createPat}; thereafter
 * only the owner's local copy holds the secret.
 */
export interface PersonalAccessToken {
  id: PatId;
  usrId: UsrId;
  /** Human-readable label set by the issuing user. 1–120 chars. */
  name: string;
  /**
   * Application-defined scope claims. The spec does not pin
   * vocabulary; adopters' authz layer interprets the strings.
   */
  scope: string[];
  status: PatStatus;
  /** Optional expiry. `null` means no expiry; valid until revoked. */
  expiresAt: Date | null;
  /**
   * Most recent successful `verifyPatToken` timestamp, or `null` if
   * never used. Eventual-consistent under burst load — the SDK
   * coalesces writes within a configurable window (60s default) per
   * ADR 0016 §"Operational notes".
   */
  lastUsedAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Successful result of {@link IdentityStore.verifyPatToken}.
 *
 * Carries only the fields a request-handling middleware needs to
 * populate audit + authz context: the pat id (audit handle), the
 * usr_id (the principal the request acts as), and the scope (the
 * application-defined claims attached to this token).
 */
export interface VerifiedPat {
  patId: PatId;
  usrId: UsrId;
  scope: string[];
}

/** Input to {@link IdentityStore.createPat}. */
export interface CreatePatInput {
  usrId: UsrId;
  /** Human-readable label, 1–120 chars. */
  name: string;
  /** Application-defined scope claims. May be empty. */
  scope: string[];
  /**
   * Optional expiry. Omit / null for no expiry. MUST be in the future
   * when set; otherwise PreconditionError fires.
   */
  expiresAt?: Date | null;
}

/**
 * Returned from {@link IdentityStore.createPat}. The plaintext `token`
 * is returned ONCE; the server retains only the Argon2id hash. Callers
 * MUST capture and surface it immediately.
 */
export interface CreatePatResult {
  pat: PersonalAccessToken;
  /** Plaintext bearer in `pat_<32hex>_<base64url>` form. */
  token: string;
}

/** Options for {@link IdentityStore.listPatsForUser}. */
export interface ListPatsForUserOptions {
  cursor?: string;
  /** Page size; clamped to [1, 200]. Default 50. */
  limit?: number;
  /** Filter by derived PAT status. */
  status?: PatStatus;
}

/**
 * Pure structural validator for the PAT bearer wire format. Returns
 * {@code true} iff the input matches `pat_<32hex>_<base64url-secret>`
 * (lowercase hex, exactly 32 chars; non-empty base64url secret).
 *
 * Performs NO database hit; suitable for fast pre-rejection in
 * middleware, and used by the cross-SDK conformance fixture
 * `spec/conformance/fixtures/identity/pat/token-format.json`.
 *
 * Note: a token that passes this check may still fail at the lookup
 * or Argon2id verify step. Conversely, every conforming SDK MUST
 * reject tokens that fail this check before any DB hit — both for
 * performance and for the timing-oracle guarantee from ADR 0016
 * §"Verification semantics".
 */
const PAT_WIRE_FORMAT = /^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$/;
export function isStructurallyValidPatToken(token: string): boolean {
  return PAT_WIRE_FORMAT.test(token);
}

/**
 * Spec floor: PAT `expiresAt` MUST be no more than 365 days from
 * `createdAt` when set (ADR 0016 §"Constraints"). Implementations MAY
 * enforce a tighter cap. 365 days = 31,536,000 seconds.
 */
export const PAT_MAX_LIFETIME_SECONDS = 365 * 24 * 60 * 60;

/**
 * security-audit-v0.3.md H2 — the dummy PHC hash used by
 * `verifyPatToken` on the missing-row path so the wall-clock time of
 * "no such pat_id" is indistinguishable from "row exists but wrong
 * secret." Without this, an attacker can probe pat_id existence via
 * timing without knowing the secret.
 *
 * The same PHC hash is in `spec/conformance/fixtures/identity/argon2id.json`
 * (it verifies to "correcthorsebatterystaple"). Generated with the
 * spec floor parameters (m=19456, t=2, p=1). PAT secrets are 43-char
 * base64url strings (32 bytes); the collision probability between
 * "correcthorsebatterystaple" and any real PAT secret is vanishing.
 *
 * Hardcoded (not regenerated at startup) so the module load is sync
 * — Argon2 is not constant-time enough to compute deterministically
 * across runs without a fixed salt, and the hash is not security
 * sensitive (it's a public dummy).
 */
export const PAT_DUMMY_PHC_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$779z4UHkLWR4w0TEo9gcHg$Gz0+nGnpokhsKi1cPlx8i74FBN1Nq0OURZ3xso1AHMU";

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * PAT wire-format utilities — v0.3 (ADR 0016).
 *
 * Wire format: pat_<32-lowercase-hex-id>_<base64url-secret>
 * Classification: bearer prefix dispatch per ADR 0016 §"Bearer routing".
 */

/** Structural regex per ADR 0016 §"Wire format". */
const PAT_WIRE_FORMAT = /^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$/;

/**
 * Returns true iff token matches the structural PAT bearer format.
 * Does NOT hit the database or Argon2id verifier.
 */
export function isStructurallyValidPatToken(token: string): boolean {
  return PAT_WIRE_FORMAT.test(token);
}

/**
 * Audit `auth.kind` discriminator per ADR 0016 §"Bearer routing".
 * Adopters writing system/cron jobs use `"system"`.
 */
export type AuthKind = "pat" | "share" | "session" | "system";

/**
 * Classify a bearer token to its auth.kind without invoking any verifier.
 * The cross-SDK conformance contract (bearer-prefix-routing.json) pins
 * the rules every SDK MUST produce identically.
 */
export function classifyBearer(token: string): AuthKind {
  if (token.startsWith("pat_")) return "pat";
  if (token.startsWith("shr_")) return "share";
  return "session";
}

/**
 * Maximum secret segment length before Argon2id is invoked.
 * Security-audit H6: pre-rejection cap to bound DoS attack surface.
 */
export const PAT_MAX_SECRET_LENGTH = 256;

/**
 * Canonical dummy Argon2id PHC string for timing-oracle defense.
 * Used on missing-row paths so wall-clock of "no such PAT" is
 * indistinguishable from "wrong secret" (security-audit H2).
 *
 * Verifies against "correcthorsebatterystaple" at spec-floor params.
 */
export const PAT_DUMMY_PHC_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$779z4UHkLWR4w0TEo9gcHg$Gz0+nGnpokhsKi1cPlx8i74FBN1Nq0OURZ3xso1AHMU";

/** 365 days in seconds — spec ceiling on PAT expires_at. */
export const PAT_MAX_LIFETIME_SECONDS = 365 * 24 * 60 * 60;

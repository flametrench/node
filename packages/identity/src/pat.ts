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

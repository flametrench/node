// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Share tokens — v0.2 primitive for time-bounded, presentation-bearer
 * resource access. See spec/docs/shares.md and spec/decisions/0012-share-tokens.md.
 *
 * A share grants the bearer of an opaque short-TTL token resource-scoped
 * access to a single (object_type, object_id) at a given relation. The
 * bearer is NOT promoted to an authenticated principal — they receive
 * only the verified relation on the verified object.
 */

import type { UsrId } from "./types.js";

export type ShrId = `shr_${string}`;

/**
 * The public share record. Token storage (SHA-256 → BYTEA) is internal;
 * the plaintext bearer credential is returned ONCE on createShare and
 * never persisted nor exposed via this type.
 */
export interface Share {
  /** Opaque id (`shr_<hex>`). */
  id: ShrId;
  objectType: string;
  objectId: string;
  relation: string;
  createdBy: UsrId;
  expiresAt: Date;
  singleUse: boolean;
  /** Set on first verify when singleUse is true. */
  consumedAt: Date | null;
  /** Soft-delete timestamp. */
  revokedAt: Date | null;
  createdAt: Date;
}

/**
 * Returned by createShare. The plaintext `token` is observable here ONLY;
 * the SDK persists only its SHA-256 hash. Callers MUST surface the token
 * to the share recipient at this point and never log it.
 */
export interface CreateShareResult {
  share: Share;
  /** Opaque base64url-encoded bearer credential, ≥ 256 bits of entropy. */
  token: string;
}

export interface CreateShareInput {
  objectType: string;
  objectId: string;
  relation: string;
  createdBy: UsrId;
  /** Lifetime in seconds. Capped at 365 days per ADR 0012. */
  expiresInSeconds: number;
  /** Default false. When true, the share is consumed on first successful verify. */
  singleUse?: boolean;
}

/**
 * Returned by verifyShareToken on success. This is enough information to
 * render the resource at the given relation; it is NOT an authenticated
 * principal and MUST NOT be promoted to a session.
 */
export interface VerifiedShare {
  shareId: ShrId;
  objectType: string;
  objectId: string;
  relation: string;
}

export interface ListSharesOptions {
  cursor?: string;
  limit?: number;
}

export interface SharesPage {
  data: Share[];
  nextCursor: string | null;
}

/**
 * The contract every share-token backend implements.
 *
 * Verification ordering is normative (per ADR 0012):
 *   1. Hash input via SHA-256.
 *   2. Look up by token_hash; missing → InvalidShareTokenError.
 *   3. Constant-time-compare; mismatch → InvalidShareTokenError.
 *   4. revoked_at non-null → ShareRevokedError.
 *   5. singleUse && consumedAt non-null → ShareConsumedError.
 *   6. expiresAt <= now → ShareExpiredError.
 *   7. If singleUse: transactionally set consumedAt = now.
 */
export interface ShareStore {
  createShare(input: CreateShareInput): Promise<CreateShareResult>;
  getShare(id: ShrId): Promise<Share>;
  /**
   * @security The returned `VerifiedShare.relation` is the relation
   * the share was minted with. The adopter MUST gate write paths on
   * this — `verifyShareToken` only proves the token is valid, not
   * that the bearer is allowed to perform the action. A common
   * footgun (security-audit-v0.3.md C2): minting `'viewer'` shares
   * and using them on both read AND write endpoints without
   * checking `verified.relation` on the writes — the SDK will not
   * stop a viewer share from posting comments / mutating the
   * resource. Mint distinct relations per intent; gate each
   * endpoint accordingly. See spec/docs/shares.md
   * §"Adopter MUST: enforce the relation field".
   */
  verifyShareToken(token: string): Promise<VerifiedShare>;
  /**
   * Idempotent. Calling on an already-revoked share returns the existing
   * record with the original revokedAt; not an error.
   */
  revokeShare(id: ShrId): Promise<Share>;
  listSharesForObject(
    objectType: string,
    objectId: string,
    options?: ListSharesOptions,
  ): Promise<SharesPage>;
}

/** Spec-mandated upper bound on share lifetime: 365 days. */
export const SHARE_MAX_TTL_SECONDS = 365 * 24 * 60 * 60;

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Reference in-memory ShareStore. O(1) verify via secondary token-hash
 * index; deterministic for tests.
 *
 * Token storage matches the Postgres reference (SHA-256 → 32 raw bytes,
 * constant-time compare on verify), so behavior is byte-identical
 * across backends.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { generate } from "@flametrench/ids";

import {
  InvalidFormatError,
  InvalidShareTokenError,
  ShareConsumedError,
  ShareExpiredError,
  ShareNotFoundError,
  ShareRevokedError,
} from "./errors.js";
import {
  SHARE_MAX_TTL_SECONDS,
  type CreateShareInput,
  type CreateShareResult,
  type ListSharesOptions,
  type Share,
  type ShareStore,
  type SharesPage,
  type ShrId,
  type VerifiedShare,
} from "./shares.js";
import { RELATION_NAME_PATTERN, TYPE_PREFIX_PATTERN } from "./types.js";

export interface InMemoryShareStoreOptions {
  /** Override the clock for deterministic tests. Default `() => new Date()`. */
  clock?: () => Date;
}

interface StoredShare {
  share: Share;
  /** Hex-encoded SHA-256 of the bearer token. Indexed for O(1) verify. */
  tokenHash: Buffer;
}

function hashToken(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function generateToken(): string {
  return randomBytes(32).toString("base64url");
}

export class InMemoryShareStore implements ShareStore {
  private readonly shares = new Map<ShrId, StoredShare>();
  /**
   * Secondary index: hex-encoded token hash → share id. Holds shares in
   * EVERY state (active, consumed, revoked, expired). The verify path
   * needs to find consumed/revoked rows to return the correct error
   * class per ADR 0012's precedence; uniqueness for collision-prevention
   * lives on the active subset only.
   */
  private readonly byTokenHash = new Map<string, ShrId>();
  private readonly clock: () => Date;

  constructor(options: InMemoryShareStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
  }

  private now(): Date {
    return this.clock();
  }

  async createShare(input: CreateShareInput): Promise<CreateShareResult> {
    if (!RELATION_NAME_PATTERN.test(input.relation)) {
      throw new InvalidFormatError(
        `relation '${input.relation}' must match ${RELATION_NAME_PATTERN}`,
        "relation",
      );
    }
    if (!TYPE_PREFIX_PATTERN.test(input.objectType)) {
      throw new InvalidFormatError(
        `objectType '${input.objectType}' must match ${TYPE_PREFIX_PATTERN}`,
        "object_type",
      );
    }
    if (input.expiresInSeconds <= 0) {
      throw new InvalidFormatError(
        `expiresInSeconds must be positive, got ${input.expiresInSeconds}`,
        "expires_in_seconds",
      );
    }
    if (input.expiresInSeconds > SHARE_MAX_TTL_SECONDS) {
      throw new InvalidFormatError(
        `expiresInSeconds exceeds the spec ceiling of ${SHARE_MAX_TTL_SECONDS} (365 days)`,
        "expires_in_seconds",
      );
    }
    const now = this.now();
    const expiresAt = new Date(now.getTime() + input.expiresInSeconds * 1000);
    const id = generate("shr") as ShrId;
    const token = generateToken();
    const tokenHash = hashToken(token);
    const share: Share = {
      id,
      objectType: input.objectType,
      objectId: input.objectId,
      relation: input.relation,
      createdBy: input.createdBy,
      expiresAt,
      singleUse: input.singleUse ?? false,
      consumedAt: null,
      revokedAt: null,
      createdAt: now,
    };
    this.shares.set(id, { share, tokenHash });
    this.byTokenHash.set(tokenHash.toString("hex"), id);
    return { share, token };
  }

  async getShare(id: ShrId): Promise<Share> {
    const entry = this.shares.get(id);
    if (!entry) throw new ShareNotFoundError(`Share ${id} not found`);
    return entry.share;
  }

  async verifyShareToken(token: string): Promise<VerifiedShare> {
    const inputHash = hashToken(token);
    const id = this.byTokenHash.get(inputHash.toString("hex"));
    if (!id) throw new InvalidShareTokenError();
    const entry = this.shares.get(id);
    if (!entry) throw new InvalidShareTokenError();
    // Defense-in-depth: timing-safe compare even though the index just hit.
    if (!timingSafeEqual(inputHash, entry.tokenHash)) {
      throw new InvalidShareTokenError();
    }
    // Spec-mandated error precedence: revoked > consumed > expired.
    if (entry.share.revokedAt !== null) throw new ShareRevokedError();
    if (entry.share.singleUse && entry.share.consumedAt !== null) {
      throw new ShareConsumedError();
    }
    const now = this.now();
    if (now.getTime() >= entry.share.expiresAt.getTime()) {
      throw new ShareExpiredError();
    }
    if (entry.share.singleUse) {
      // Atomic consume — set consumedAt on the public record. We
      // intentionally KEEP the byTokenHash entry so a second verify
      // can find the row and return ShareConsumedError (not
      // InvalidShareTokenError). The Postgres equivalent is `UPDATE
      // ... WHERE consumed_at IS NULL RETURNING …`, which is what the
      // PostgresShareStore uses for race-correctness.
      const consumed: Share = { ...entry.share, consumedAt: now };
      this.shares.set(id, { ...entry, share: consumed });
    }
    return {
      shareId: id,
      objectType: entry.share.objectType,
      objectId: entry.share.objectId,
      relation: entry.share.relation,
    };
  }

  async revokeShare(id: ShrId): Promise<Share> {
    const entry = this.shares.get(id);
    if (!entry) throw new ShareNotFoundError(`Share ${id} not found`);
    if (entry.share.revokedAt !== null) {
      // Idempotent: return the existing record with the original timestamp.
      return entry.share;
    }
    const revoked: Share = { ...entry.share, revokedAt: this.now() };
    this.shares.set(id, { ...entry, share: revoked });
    // Don't drop the byTokenHash entry — verify must find the row to
    // return ShareRevokedError, not InvalidShareTokenError.
    return revoked;
  }

  async listSharesForObject(
    objectType: string,
    objectId: string,
    options: ListSharesOptions = {},
  ): Promise<SharesPage> {
    const limit = Math.min(options.limit ?? 50, 200);
    const cursor = options.cursor;
    const all = [...this.shares.values()]
      .map((e) => e.share)
      .filter(
        (s) =>
          s.objectType === objectType
          && s.objectId === objectId
          && (cursor === undefined || s.id > cursor),
      )
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const data = all.slice(0, limit);
    const nextCursor = all.length > limit && data.length > 0
      ? data[data.length - 1]!.id
      : null;
    return { data, nextCursor };
  }
}

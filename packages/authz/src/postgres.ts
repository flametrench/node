// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * PostgresTupleStore — Postgres-backed implementation of TupleStore.
 *
 * Mirrors the in-memory implementation byte-for-byte at the SDK
 * boundary; the difference is durability and concurrency. Schema lives
 * in spec/reference/postgres.sql (the `tup` table). Tests vendor a
 * snapshot of that schema and gate on AUTHZ_POSTGRES_URL — see
 * test/postgres.test.ts.
 *
 * Design notes:
 *   - All ID columns store native UUID. Wire-format prefixed IDs
 *     (`usr_<hex>`, `tup_<hex>`) are computed at the SDK boundary via
 *     @flametrench/ids encode/decode.
 *   - The natural-key UNIQUE constraint
 *     (subject_type, subject_id, relation, object_type, object_id)
 *     already lives in the reference DDL; this store relies on it for
 *     duplicate detection rather than re-implementing the check.
 *   - check() uses EXISTS for the hot path. checkAny() collapses to
 *     a single query with `relation = ANY(...)` so set-form checks
 *     are one round-trip.
 *   - Rewrite-rule support (ADR 0007) is exact-match only here in v0.2:
 *     bridging the synchronous `evaluate()` evaluator to async Postgres
 *     queries is tracked for v0.3. Adopters with rule needs can pull
 *     the relevant tuple subset into memory and use InMemoryTupleStore
 *     with the `rules` option.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { decode, decodeAny, encode, generate } from "@flametrench/ids";
import type { Pool, PoolClient } from "pg";

// ─── ADR 0013 savepoint helpers ───

/** See identity/src/postgres.ts for rationale. */
function callerName(): string {
  const stack = new Error().stack ?? "";
  const lines = stack.split("\n");
  const target = lines[3] ?? "";
  const m = target.match(/at\s+(?:async\s+)?(?:[\w$.]+\.)?([\w$]+)\s/);
  return m?.[1] ?? "tx";
}

function makeSavepointName(method: string): string {
  const sanitized = method.replace(/[^A-Za-z0-9]/g, "");
  const safe = sanitized.length > 0 ? sanitized : "tx";
  const rand = randomBytes(4).toString("hex");
  return `ft_${safe}_${rand}`;
}

/**
 * Connection types accepted by the Postgres adapters. See ADR 0013 + the
 * identity/tenancy adapter docstrings for the contract.
 */
export type PostgresAuthzClient = Pool | PoolClient;

function clientIsCallerOwned(client: PostgresAuthzClient): boolean {
  return typeof (client as { release?: unknown }).release === "function";
}

async function withSavepoint<T>(
  c: PoolClient,
  fn: () => Promise<T>,
  caller: string,
): Promise<T> {
  const sp = makeSavepointName(caller);
  await c.query(`SAVEPOINT ${sp}`);
  try {
    const out = await fn();
    await c.query(`RELEASE SAVEPOINT ${sp}`);
    return out;
  } catch (err) {
    await c.query(`ROLLBACK TO SAVEPOINT ${sp}`).catch(() => {});
    await c.query(`RELEASE SAVEPOINT ${sp}`).catch(() => {});
    throw err;
  }
}

import {
  DuplicateTupleError,
  EmptyRelationSetError,
  InvalidFormatError,
  InvalidShareTokenError,
  PreconditionError,
  ShareConsumedError,
  ShareExpiredError,
  ShareNotFoundError,
  ShareRevokedError,
  TupleNotFoundError,
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
import type { TupleStore } from "./store.js";
import {
  RELATION_NAME_PATTERN,
  TYPE_PREFIX_PATTERN,
  type CheckInput,
  type CheckResult,
  type CheckSetInput,
  type CreateTupleInput,
  type ListOptions,
  type Page,
  type SubjectType,
  type TupId,
  type Tuple,
  type UsrId,
} from "./types.js";

interface TupRow {
  id: string;
  subject_type: string;
  subject_id: string;
  relation: string;
  object_type: string;
  object_id: string;
  created_at: Date;
  created_by: string | null;
}

function rowToTuple(r: TupRow): Tuple {
  return {
    id: encode("tup", r.id) as TupId,
    subjectType: r.subject_type as SubjectType,
    subjectId: encode("usr", r.subject_id) as UsrId,
    relation: r.relation,
    objectType: r.object_type,
    objectId: r.object_id,
    createdAt: r.created_at,
    createdBy: r.created_by !== null ? (encode("usr", r.created_by) as UsrId) : null,
  };
}

function wireToUuid(wireId: string): string {
  return decode(wireId).uuid;
}

/**
 * Decode an `object_id` to a Postgres-bindable UUID string.
 *
 * `object_type` is application-defined (per spec/docs/authorization.md
 * and ADR 0001), so `object_id` may legitimately arrive as:
 *   1. A wire-format ID with a non-registered prefix (e.g. `proj_<hex>`,
 *      `file_<hex>`) — extract the UUID via `decodeAny` so app-defined
 *      prefixes are accepted in addition to registered types.
 *   2. A raw 32-character hex UUID — accept as-is; Postgres UUID parsing
 *      handles both 32-hex and hyphenated forms.
 *   3. A canonical hyphenated UUID — also accepted as-is.
 *
 * Closes spec#8.
 */
function objectIdToUuid(objectId: string): string {
  if (/^[a-z]{2,6}_[0-9a-f]{32}$/.test(objectId)) {
    return decodeAny(objectId).uuid;
  }
  return objectId;
}

export interface PostgresTupleStoreOptions {
  /** Override the clock for deterministic tests. */
  clock?: () => Date;
}

export class PostgresTupleStore implements TupleStore {
  private readonly clock: () => Date;

  constructor(
    private readonly pool: PostgresAuthzClient,
    options: PostgresTupleStoreOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
  }

  private now(): Date {
    return this.clock();
  }

  /**
   * Shield $fn with a savepoint when nested in a caller-owned outer
   * transaction; pass through directly when standalone (Pool). See ADR 0013
   * — single-statement INSERT/UPDATE/DELETE methods need shielding so a
   * constraint violation rolls back to the savepoint instead of poisoning
   * the outer transaction (Postgres SQLSTATE 25P02).
   */
  private async nested<T>(fn: () => Promise<T>): Promise<T> {
    if (!clientIsCallerOwned(this.pool)) return fn();
    return withSavepoint(this.pool as PoolClient, fn, callerName());
  }

  // ─── Mutations ───

  async createTuple(input: CreateTupleInput): Promise<Tuple> {
    if (!RELATION_NAME_PATTERN.test(input.relation)) {
      throw new InvalidFormatError(
        `relation ${JSON.stringify(input.relation)} does not match ${RELATION_NAME_PATTERN}`,
        "relation",
      );
    }
    if (!TYPE_PREFIX_PATTERN.test(input.objectType)) {
      throw new InvalidFormatError(
        `objectType ${JSON.stringify(input.objectType)} does not match ${TYPE_PREFIX_PATTERN}`,
        "object_type",
      );
    }
    return this.nested(async () => {
      const id = decode(generate("tup")).uuid;
      const subjectUuid = wireToUuid(input.subjectId);
      const objectUuid = objectIdToUuid(input.objectId);
      const createdByUuid = input.createdBy ? wireToUuid(input.createdBy) : null;
      const now = this.now();
      // ON CONFLICT DO NOTHING avoids raising 23505 inside an outer
      // transaction (ADR 0013). On natural-key conflict the INSERT
      // returns no rows; we then SELECT the existing row and raise
      // DuplicateTupleError. The previous catch-and-SELECT pattern was
      // incompatible with savepoint shielding because the follow-up
      // SELECT would run inside a Postgres-aborted transaction.
      const { rows } = await this.pool.query<TupRow>(
        `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (subject_type, subject_id, relation, object_type, object_id) DO NOTHING
         RETURNING id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by`,
        [
          id,
          input.subjectType,
          subjectUuid,
          input.relation,
          input.objectType,
          objectUuid,
          now,
          createdByUuid,
        ],
      );
      if (rows.length > 0) {
        return rowToTuple(rows[0]!);
      }
      const { rows: existing } = await this.pool.query<{ id: string }>(
        `SELECT id FROM tup
         WHERE subject_type = $1 AND subject_id = $2 AND relation = $3
           AND object_type = $4 AND object_id = $5`,
        [input.subjectType, subjectUuid, input.relation, input.objectType, objectUuid],
      );
      if (existing.length === 0) {
        // Race: another connection inserted-then-deleted between our
        // ON CONFLICT and the SELECT. Surface a generic error so callers
        // can retry.
        throw new Error("Tuple natural-key conflict resolved after insert lost the row; retry.");
      }
      throw new DuplicateTupleError(
        `Tuple with identical natural key already exists`,
        encode("tup", existing[0]!.id) as TupId,
      );
    });
  }

  async deleteTuple(id: TupId): Promise<void> {
    await this.nested(async () => {
      const { rowCount } = await this.pool.query(
        `DELETE FROM tup WHERE id = $1`,
        [wireToUuid(id)],
      );
      if (rowCount === 0) {
        throw new TupleNotFoundError(`Tuple ${id} not found`);
      }
    });
  }

  async cascadeRevokeSubject(
    subjectType: SubjectType,
    subjectId: UsrId,
  ): Promise<number> {
    return this.nested(async () => {
      const { rowCount } = await this.pool.query(
        `DELETE FROM tup WHERE subject_type = $1 AND subject_id = $2`,
        [subjectType, wireToUuid(subjectId)],
      );
      return rowCount ?? 0;
    });
  }

  // ─── check() / checkAny() ───

  async check(input: CheckInput): Promise<CheckResult> {
    return this.checkAny({ ...input, relations: [input.relation] });
  }

  async checkAny(input: CheckSetInput): Promise<CheckResult> {
    if (input.relations.length === 0) {
      throw new EmptyRelationSetError();
    }
    // PostgresTupleStore is exact-match only in v0.2 (the load-bearing
    // path for production adopters). Rewrite-rule support requires
    // bridging the SDK's synchronous `evaluate()` to Postgres's async
    // queries — design tracked for v0.3. Adopters with rule needs:
    // bring the relevant tuple subset into memory and use
    // InMemoryTupleStore with `rules` option.
    const subjectUuid = wireToUuid(input.subjectId);
    const { rows } = await this.pool.query<{ id: string }>(
      `SELECT id FROM tup
       WHERE subject_type = $1 AND subject_id = $2
         AND relation = ANY($3) AND object_type = $4 AND object_id = $5
       LIMIT 1`,
      [
        input.subjectType,
        subjectUuid,
        input.relations,
        input.objectType,
        objectIdToUuid(input.objectId),
      ],
    );
    const allowed = rows.length > 0;
    return {
      allowed,
      matchedTupleId: allowed ? (encode("tup", rows[0]!.id) as TupId) : null,
    };
  }

  // ─── Read accessors ───

  async getTuple(id: TupId): Promise<Tuple> {
    const { rows } = await this.pool.query<TupRow>(
      `SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
       FROM tup WHERE id = $1`,
      [wireToUuid(id)],
    );
    if (rows.length === 0) throw new TupleNotFoundError(`Tuple ${id} not found`);
    return rowToTuple(rows[0]!);
  }

  async listTuplesBySubject(
    subjectType: SubjectType,
    subjectId: UsrId,
    options: ListOptions = {},
  ): Promise<Page<Tuple>> {
    const limit = Math.min(options.limit ?? 50, 200);
    const cursor = options.cursor;
    const { rows } = await this.pool.query<TupRow>(
      `SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
       FROM tup
       WHERE subject_type = $1 AND subject_id = $2
         ${cursor ? "AND id > $4" : ""}
       ORDER BY id
       LIMIT $3`,
      cursor
        ? [subjectType, wireToUuid(subjectId), limit + 1, wireToUuid(cursor)]
        : [subjectType, wireToUuid(subjectId), limit + 1],
    );
    return paginate(rows, limit);
  }

  async listTuplesByObject(
    objectType: string,
    objectId: string,
    relation?: string,
    options: ListOptions = {},
  ): Promise<Page<Tuple>> {
    const limit = Math.min(options.limit ?? 50, 200);
    const cursor = options.cursor;
    const params: unknown[] = [objectType, objectIdToUuid(objectId)];
    let where = "object_type = $1 AND object_id = $2";
    if (relation !== undefined) {
      params.push(relation);
      where += ` AND relation = $${params.length}`;
    }
    params.push(limit + 1);
    const limitParam = params.length;
    if (cursor) {
      params.push(wireToUuid(cursor));
      where += ` AND id > $${params.length}`;
    }
    const { rows } = await this.pool.query<TupRow>(
      `SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
       FROM tup
       WHERE ${where}
       ORDER BY id
       LIMIT $${limitParam}`,
      params,
    );
    return paginate(rows, limit);
  }
}

function paginate(rows: TupRow[], limit: number): Page<Tuple> {
  const data = rows.slice(0, limit).map(rowToTuple);
  const nextCursor =
    rows.length > limit ? (data[data.length - 1]?.id ?? null) : null;
  return { data, nextCursor };
}


// ─── PostgresShareStore (ADR 0012) ──────────────────────────────────

interface ShrRow {
  id: string;
  token_hash: Buffer;
  object_type: string;
  object_id: string;
  relation: string;
  created_by: string;
  expires_at: Date;
  single_use: boolean;
  consumed_at: Date | null;
  revoked_at: Date | null;
  created_at: Date;
}

const SHR_COLS =
  "id, token_hash, object_type, object_id, relation, created_by, "
  + "expires_at, single_use, consumed_at, revoked_at, created_at";

function rowToShare(r: ShrRow): Share {
  return {
    id: encode("shr", r.id) as ShrId,
    objectType: r.object_type,
    objectId: r.object_id,
    relation: r.relation,
    createdBy: encode("usr", r.created_by) as UsrId,
    expiresAt: r.expires_at,
    singleUse: r.single_use,
    consumedAt: r.consumed_at,
    revokedAt: r.revoked_at,
    createdAt: r.created_at,
  };
}

function hashTokenBytes(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function generateShareToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Postgres-backed ShareStore. Mirrors {@link InMemoryShareStore} byte-
 * for-byte at the SDK boundary.
 *
 * Verification is one round-trip on the partial-unique `shr_token_hash_idx`
 * (which excludes consumed + revoked rows). Single-use consumption uses
 * `UPDATE ... WHERE consumed_at IS NULL RETURNING ...` so concurrent
 * verifies of a single-use token race-correctly to exactly one success.
 */
export class PostgresShareStore implements ShareStore {
  private readonly clock: () => Date;

  constructor(
    private readonly pool: PostgresAuthzClient,
    options: { clock?: () => Date } = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
  }

  private now(): Date {
    return this.clock();
  }

  private async tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
    if (clientIsCallerOwned(this.pool)) {
      const c = this.pool as PoolClient;
      return withSavepoint(c, () => fn(c), callerName());
    }
    const c = await (this.pool as Pool).connect();
    try {
      await c.query("BEGIN");
      const out = await fn(c);
      await c.query("COMMIT");
      return out;
    } catch (err) {
      await c.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      c.release();
    }
  }

  private async nested<T>(fn: () => Promise<T>): Promise<T> {
    if (!clientIsCallerOwned(this.pool)) return fn();
    return withSavepoint(this.pool as PoolClient, fn, callerName());
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
    return this.nested(async () => {
      const createdByUuid = wireToUuid(input.createdBy);
      // ADR 0012: createdBy MUST resolve to an active user. The DDL FK
      // enforces existence; status is checked here at the SDK layer.
      // Suspended/revoked users with leaked credentials cannot mint shares.
      const userStatus = await this.pool.query<{ status: string }>(
        `SELECT status FROM usr WHERE id = $1`,
        [createdByUuid],
      );
      if (userStatus.rows.length === 0) {
        throw new PreconditionError(
          `createdBy ${input.createdBy} does not exist`,
          "creator_not_found",
        );
      }
      if (userStatus.rows[0]!.status !== "active") {
        throw new PreconditionError(
          `createdBy ${input.createdBy} is ${userStatus.rows[0]!.status}; only active users can mint shares`,
          "creator_not_active",
        );
      }
      const id = decode(generate("shr")).uuid;
      const token = generateShareToken();
      const tokenHash = hashTokenBytes(token);
      const now = this.now();
      const expiresAt = new Date(now.getTime() + input.expiresInSeconds * 1000);
      const { rows } = await this.pool.query<ShrRow>(
        `INSERT INTO shr (id, token_hash, object_type, object_id, relation,
                          created_by, expires_at, single_use, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING ${SHR_COLS}`,
        [
          id,
          tokenHash,
          input.objectType,
          objectIdToUuid(input.objectId),
          input.relation,
          createdByUuid,
          expiresAt,
          input.singleUse ?? false,
          now,
        ],
      );
      return { share: rowToShare(rows[0]!), token };
    });
  }

  async getShare(id: ShrId): Promise<Share> {
    const { rows } = await this.pool.query<ShrRow>(
      `SELECT ${SHR_COLS} FROM shr WHERE id = $1`,
      [wireToUuid(id)],
    );
    if (rows.length === 0) {
      throw new ShareNotFoundError(`Share ${id} not found`);
    }
    return rowToShare(rows[0]!);
  }

  async verifyShareToken(token: string): Promise<VerifiedShare> {
    const inputHash = hashTokenBytes(token);
    return this.tx(async (c) => {
      // Lookup is done WITHOUT the partial-unique-index filter so we can
      // distinguish revoked / consumed / expired and return the right
      // error class. The index still serves the hot path; we add the
      // explicit row-state checks for clean error semantics.
      const sel = await c.query<ShrRow>(
        `SELECT ${SHR_COLS} FROM shr WHERE token_hash = $1
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
        [inputHash],
      );
      if (sel.rows.length === 0) throw new InvalidShareTokenError();
      const r = sel.rows[0]!;
      // Defense-in-depth: timing-safe compare on the BYTEA column.
      if (!timingSafeEqual(inputHash, r.token_hash)) {
        throw new InvalidShareTokenError();
      }
      // Spec error precedence: revoked > consumed > expired.
      if (r.revoked_at !== null) throw new ShareRevokedError();
      if (r.single_use && r.consumed_at !== null) throw new ShareConsumedError();
      const now = this.now();
      if (now.getTime() >= r.expires_at.getTime()) {
        throw new ShareExpiredError();
      }
      if (r.single_use) {
        // Atomic consume — concurrent verifies race here. The
        // `WHERE consumed_at IS NULL` is what makes the second loser.
        const upd = await c.query<{ id: string }>(
          `UPDATE shr SET consumed_at = $2
           WHERE id = $1 AND consumed_at IS NULL
           RETURNING id`,
          [r.id, now],
        );
        if (upd.rows.length === 0) throw new ShareConsumedError();
      }
      return {
        shareId: encode("shr", r.id) as ShrId,
        objectType: r.object_type,
        objectId: r.object_id,
        relation: r.relation,
      };
    });
  }

  async revokeShare(id: ShrId): Promise<Share> {
    return this.nested(async () => {
      const uuid = wireToUuid(id);
      const { rows } = await this.pool.query<ShrRow>(
        `UPDATE shr SET revoked_at = COALESCE(revoked_at, $2)
         WHERE id = $1
         RETURNING ${SHR_COLS}`,
        [uuid, this.now()],
      );
      if (rows.length === 0) {
        throw new ShareNotFoundError(`Share ${id} not found`);
      }
      return rowToShare(rows[0]!);
    });
  }

  async listSharesForObject(
    objectType: string,
    objectId: string,
    options: ListSharesOptions = {},
  ): Promise<SharesPage> {
    const limit = Math.min(options.limit ?? 50, 200);
    const cursor = options.cursor;
    const params: unknown[] = [objectType, objectIdToUuid(objectId)];
    let where = "object_type = $1 AND object_id = $2";
    if (cursor !== undefined) {
      params.push(wireToUuid(cursor));
      where += ` AND id > $${params.length}`;
    }
    params.push(limit + 1);
    const limitParam = params.length;
    const { rows } = await this.pool.query<ShrRow>(
      `SELECT ${SHR_COLS} FROM shr
       WHERE ${where}
       ORDER BY id LIMIT $${limitParam}`,
      params,
    );
    const data = rows.slice(0, limit).map(rowToShare);
    const nextCursor =
      rows.length > limit ? (data[data.length - 1]?.id ?? null) : null;
    return { data, nextCursor };
  }
}

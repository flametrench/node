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

import { decode, encode, generate } from "@flametrench/ids";
import type { Pool } from "pg";

import {
  DuplicateTupleError,
  EmptyRelationSetError,
  InvalidFormatError,
  TupleNotFoundError,
} from "./errors.js";
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

export interface PostgresTupleStoreOptions {
  /** Override the clock for deterministic tests. */
  clock?: () => Date;
}

export class PostgresTupleStore implements TupleStore {
  private readonly clock: () => Date;

  constructor(
    private readonly pool: Pool,
    options: PostgresTupleStoreOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
  }

  private now(): Date {
    return this.clock();
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
    const id = decode(generate("tup")).uuid;
    const subjectUuid = wireToUuid(input.subjectId);
    const createdByUuid = input.createdBy ? wireToUuid(input.createdBy) : null;
    const now = this.now();
    try {
      const { rows } = await this.pool.query<TupRow>(
        `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by`,
        [
          id,
          input.subjectType,
          subjectUuid,
          input.relation,
          input.objectType,
          input.objectId,
          now,
          createdByUuid,
        ],
      );
      return rowToTuple(rows[0]!);
    } catch (err) {
      if (isUniqueViolation(err)) {
        const { rows } = await this.pool.query<{ id: string }>(
          `SELECT id FROM tup
           WHERE subject_type = $1 AND subject_id = $2 AND relation = $3
             AND object_type = $4 AND object_id = $5`,
          [input.subjectType, subjectUuid, input.relation, input.objectType, input.objectId],
        );
        if (rows.length > 0) {
          throw new DuplicateTupleError(
            `Tuple with identical natural key already exists`,
            encode("tup", rows[0]!.id) as TupId,
          );
        }
      }
      throw err;
    }
  }

  async deleteTuple(id: TupId): Promise<void> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM tup WHERE id = $1`,
      [wireToUuid(id)],
    );
    if (rowCount === 0) {
      throw new TupleNotFoundError(`Tuple ${id} not found`);
    }
  }

  async cascadeRevokeSubject(
    subjectType: SubjectType,
    subjectId: UsrId,
  ): Promise<number> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM tup WHERE subject_type = $1 AND subject_id = $2`,
      [subjectType, wireToUuid(subjectId)],
    );
    return rowCount ?? 0;
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
        input.objectId,
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
    const params: unknown[] = [objectType, objectId];
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

/** Postgres SQLSTATE 23505 = unique_violation. */
function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object"
    && err !== null
    && (err as { code?: string }).code === "23505"
  );
}

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type {
  CheckInput,
  CheckResult,
  CheckSetInput,
  CreateTupleInput,
  ListOptions,
  Page,
  SubjectType,
  TupId,
  Tuple,
  UsrId,
} from "./types.js";

/**
 * The `TupleStore` interface is the contract every authorization backend
 * fulfills. An in-memory implementation ships with this package; a
 * Postgres-backed implementation is planned for a future release.
 *
 * **Exact-match semantics.** In v0.1, `check()` returns true iff a tuple
 * with the exact 5-tuple key exists. No derivation, no inheritance, no
 * group expansion. This is the spec's load-bearing simplification from
 * ADR 0001. Any implementation that returns true for a missing tuple —
 * even via a reasonable inference — is NOT conformant.
 */
export interface TupleStore {
  // ─── Mutations ───

  createTuple(input: CreateTupleInput): Promise<Tuple>;

  /**
   * Delete a tuple by id. Throws TupleNotFoundError if the id does not
   * refer to a stored tuple.
   */
  deleteTuple(id: TupId): Promise<void>;

  /**
   * Delete every tuple with the given subject. Used by identity / tenancy
   * layers when a user or membership is revoked. Returns the number of
   * rows deleted.
   */
  cascadeRevokeSubject(subjectType: SubjectType, subjectId: UsrId): Promise<number>;

  // ─── The authz primitive ───

  /** Single-relation check. */
  check(input: CheckInput): Promise<CheckResult>;

  /**
   * Set-form check. Succeeds if any tuple matching any of the given
   * relations exists. Equivalent to the logical OR of single-relation
   * checks but atomic and, in persistent stores, executed as one query.
   */
  checkAny(input: CheckSetInput): Promise<CheckResult>;

  // ─── Read accessors ───

  getTuple(id: TupId): Promise<Tuple>;

  listTuplesBySubject(
    subjectType: SubjectType,
    subjectId: UsrId,
    options?: ListOptions,
  ): Promise<Page<Tuple>>;

  listTuplesByObject(
    objectType: string,
    objectId: string,
    relation?: string,
    options?: ListOptions,
  ): Promise<Page<Tuple>>;
}

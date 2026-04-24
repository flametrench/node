// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate } from "@flametrench/ids";

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

export interface InMemoryTupleStoreOptions {
  /** Override the clock for deterministic tests. Default `() => new Date()`. */
  clock?: () => Date;
}

/**
 * An in-memory TupleStore. O(n) scans for check() — acceptable for tests,
 * documentation, and small applications; a Postgres-backed store with
 * proper indexes is planned for production workloads.
 *
 * Maintains a secondary index on the 5-tuple natural key to detect
 * duplicate inserts in O(1), matching the spec's uniqueness invariant.
 */
export class InMemoryTupleStore implements TupleStore {
  private readonly tuples = new Map<TupId, Tuple>();
  /** Secondary index: natural key → tuple id. */
  private readonly keyIndex = new Map<string, TupId>();
  private readonly clock: () => Date;

  constructor(options: InMemoryTupleStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
  }

  private now(): Date {
    return this.clock();
  }

  private newTupId(): TupId {
    return generate("tup") as TupId;
  }

  private static naturalKey(
    subjectType: SubjectType,
    subjectId: UsrId,
    relation: string,
    objectType: string,
    objectId: string,
  ): string {
    return `${subjectType}|${subjectId}|${relation}|${objectType}|${objectId}`;
  }

  private static validateFormats(
    relation: string,
    objectType: string,
  ): void {
    if (!RELATION_NAME_PATTERN.test(relation)) {
      throw new InvalidFormatError(
        `relation '${relation}' must match ${RELATION_NAME_PATTERN}`,
        "relation",
      );
    }
    if (!TYPE_PREFIX_PATTERN.test(objectType)) {
      throw new InvalidFormatError(
        `objectType '${objectType}' must match ${TYPE_PREFIX_PATTERN}`,
        "object_type",
      );
    }
  }

  // ─── Mutations ───

  async createTuple(input: CreateTupleInput): Promise<Tuple> {
    InMemoryTupleStore.validateFormats(input.relation, input.objectType);
    const key = InMemoryTupleStore.naturalKey(
      input.subjectType,
      input.subjectId,
      input.relation,
      input.objectType,
      input.objectId,
    );
    const existing = this.keyIndex.get(key);
    if (existing !== undefined) {
      throw new DuplicateTupleError(
        `Tuple with identical natural key already exists`,
        existing,
      );
    }
    const tup: Tuple = {
      id: this.newTupId(),
      subjectType: input.subjectType,
      subjectId: input.subjectId,
      relation: input.relation,
      objectType: input.objectType,
      objectId: input.objectId,
      createdAt: this.now(),
      createdBy: input.createdBy ?? null,
    };
    this.tuples.set(tup.id, tup);
    this.keyIndex.set(key, tup.id);
    return tup;
  }

  async deleteTuple(id: TupId): Promise<void> {
    const tup = this.tuples.get(id);
    if (!tup) throw new TupleNotFoundError(`Tuple ${id} not found`);
    this.tuples.delete(id);
    this.keyIndex.delete(
      InMemoryTupleStore.naturalKey(
        tup.subjectType,
        tup.subjectId,
        tup.relation,
        tup.objectType,
        tup.objectId,
      ),
    );
  }

  async cascadeRevokeSubject(
    subjectType: SubjectType,
    subjectId: UsrId,
  ): Promise<number> {
    let n = 0;
    for (const [id, tup] of this.tuples.entries()) {
      if (tup.subjectType === subjectType && tup.subjectId === subjectId) {
        this.tuples.delete(id);
        this.keyIndex.delete(
          InMemoryTupleStore.naturalKey(
            tup.subjectType,
            tup.subjectId,
            tup.relation,
            tup.objectType,
            tup.objectId,
          ),
        );
        n++;
      }
    }
    return n;
  }

  // ─── check() primitives ───

  async check(input: CheckInput): Promise<CheckResult> {
    const key = InMemoryTupleStore.naturalKey(
      input.subjectType,
      input.subjectId,
      input.relation,
      input.objectType,
      input.objectId,
    );
    const tupId = this.keyIndex.get(key) ?? null;
    return { allowed: tupId !== null, matchedTupleId: tupId };
  }

  async checkAny(input: CheckSetInput): Promise<CheckResult> {
    if (input.relations.length === 0) {
      throw new EmptyRelationSetError();
    }
    for (const relation of input.relations) {
      const key = InMemoryTupleStore.naturalKey(
        input.subjectType,
        input.subjectId,
        relation,
        input.objectType,
        input.objectId,
      );
      const tupId = this.keyIndex.get(key);
      if (tupId !== undefined) {
        return { allowed: true, matchedTupleId: tupId };
      }
    }
    return { allowed: false, matchedTupleId: null };
  }

  // ─── Read accessors ───

  async getTuple(id: TupId): Promise<Tuple> {
    const tup = this.tuples.get(id);
    if (!tup) throw new TupleNotFoundError(`Tuple ${id} not found`);
    return tup;
  }

  async listTuplesBySubject(
    subjectType: SubjectType,
    subjectId: UsrId,
    options: ListOptions = {},
  ): Promise<Page<Tuple>> {
    const matching = [...this.tuples.values()]
      .filter(
        (t) => t.subjectType === subjectType && t.subjectId === subjectId,
      )
      .sort((a, b) => a.id.localeCompare(b.id));
    return this.paginate(matching, options);
  }

  async listTuplesByObject(
    objectType: string,
    objectId: string,
    relation?: string,
    options: ListOptions = {},
  ): Promise<Page<Tuple>> {
    const matching = [...this.tuples.values()]
      .filter(
        (t) =>
          t.objectType === objectType &&
          t.objectId === objectId &&
          (relation === undefined || t.relation === relation),
      )
      .sort((a, b) => a.id.localeCompare(b.id));
    return this.paginate(matching, options);
  }

  private paginate<T extends { id: string }>(
    all: T[],
    options: ListOptions,
  ): Page<T> {
    const limit = options.limit ?? 50;
    const startIndex = options.cursor
      ? all.findIndex((x) => x.id > options.cursor!)
      : 0;
    const start = startIndex < 0 ? all.length : startIndex;
    const data = all.slice(start, start + limit);
    const nextCursor =
      start + limit < all.length ? (data[data.length - 1]?.id ?? null) : null;
    return { data, nextCursor };
  }
}

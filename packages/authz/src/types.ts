// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Flametrench v0.1 authorization types.
 *
 * The sole authz primitive is the relational tuple (subject, relation,
 * object). `check()` returns true iff a matching tuple exists. There is
 * no derivation, no rewrite rules, no group expansion in v0.1 — those
 * are deferred to v0.2+ per ADR 0001.
 */

/** Subject types permitted in v0.1. `grp` is a v0.2+ addition. */
export type SubjectType = "usr";

export type UsrId = `usr_${string}`;
export type TupId = `tup_${string}`;

/**
 * Built-in relations registered in v0.1. Applications MAY register custom
 * relation names matching `^[a-z_]{2,32}$`; the spec imposes no semantics
 * on them. The six built-ins are typed as a literal union for
 * autocomplete; custom names are accepted anywhere a `string` relation
 * would be.
 */
export type BuiltinRelation =
  | "owner"
  | "admin"
  | "member"
  | "guest"
  | "viewer"
  | "editor";

/** Validator matching the spec's relation-name format (docs/authorization.md). */
export const RELATION_NAME_PATTERN = /^[a-z_]{2,32}$/;

/** Validator matching the spec's type-prefix format (docs/ids.md). */
export const TYPE_PREFIX_PATTERN = /^[a-z]{2,6}$/;

export interface Tuple {
  /** Opaque id of this tuple (`tup_<hex>`). */
  id: TupId;
  subjectType: SubjectType;
  subjectId: UsrId;
  relation: string;
  objectType: string;
  objectId: string;
  createdAt: Date;
  createdBy: UsrId | null;
}

// ─── Operation inputs ───

export interface CreateTupleInput {
  subjectType: SubjectType;
  subjectId: UsrId;
  relation: string;
  objectType: string;
  objectId: string;
  createdBy?: UsrId;
}

/**
 * The single-relation form of check(). Use this when you want precise
 * attribution of which relation authorized the request.
 */
export interface CheckInput {
  subjectType: SubjectType;
  subjectId: UsrId;
  relation: string;
  objectType: string;
  objectId: string;
}

/**
 * The set-form of check(). Returns true if any tuple exists for any of
 * the given relations. The array MUST be non-empty.
 */
export interface CheckSetInput {
  subjectType: SubjectType;
  subjectId: UsrId;
  relations: string[];
  objectType: string;
  objectId: string;
}

export interface CheckResult {
  allowed: boolean;
  /**
   * The matched tuple id, if `allowed === true`. Implementations MAY
   * return `null` (e.g. to avoid disclosing which tuple satisfied).
   */
  matchedTupleId: TupId | null;
}

export interface ListOptions {
  cursor?: string;
  limit?: number;
}

export interface Page<T> {
  data: T[];
  nextCursor: string | null;
}

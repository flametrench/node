// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/authz — relational tuples and exact-match check().
 *
 * The spec-normative authorization layer for Flametrench v0.1. See
 * spec/docs/authorization.md and spec/decisions/0001-authorization-model.md.
 */

export type {
  BuiltinRelation,
  CheckInput,
  CheckResult,
  CheckSetInput,
  CreateTupleInput,
  ListOptions,
  Page,
  SubjectType,
  Tuple,
  TupId,
  UsrId,
} from "./types.js";
export { RELATION_NAME_PATTERN, TYPE_PREFIX_PATTERN } from "./types.js";

export type { TupleStore } from "./store.js";

export {
  InMemoryTupleStore,
  type InMemoryTupleStoreOptions,
} from "./in-memory.js";

export {
  AuthzError,
  DuplicateTupleError,
  EmptyRelationSetError,
  InvalidFormatError,
  TupleNotFoundError,
} from "./errors.js";

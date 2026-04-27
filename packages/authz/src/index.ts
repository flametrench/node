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
  EvaluationLimitExceededError,
  InvalidFormatError,
  InvalidShareTokenError,
  ShareConsumedError,
  ShareExpiredError,
  ShareNotFoundError,
  ShareRevokedError,
  TupleNotFoundError,
} from "./errors.js";

export {
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_FAN_OUT,
  type ComputedUserset,
  type Rule,
  type RuleNode,
  type Rules,
  type ThisNode,
  type TupleToUserset,
} from "./rewrite-rules.js";

// v0.2 share tokens (ADR 0012).
export type {
  CreateShareInput,
  CreateShareResult,
  ListSharesOptions,
  Share,
  ShareStore,
  SharesPage,
  ShrId,
  VerifiedShare,
} from "./shares.js";
export { SHARE_MAX_TTL_SECONDS } from "./shares.js";
export {
  InMemoryShareStore,
  type InMemoryShareStoreOptions,
} from "./in-memory-shares.js";

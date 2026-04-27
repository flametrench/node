// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Base class for every authorization-layer error. Carries a stable,
 * machine-readable `code` matching the OpenAPI Error envelope.
 */
export class AuthzError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = "AuthzError";
  }
}

/** A tuple with the requested id does not exist. */
export class TupleNotFoundError extends AuthzError {
  constructor(message: string) {
    super(message, "not_found");
    this.name = "TupleNotFoundError";
  }
}

/**
 * A tuple with the same natural key `(subject_type, subject_id, relation,
 * object_type, object_id)` already exists. Callers MAY treat this as an
 * idempotency success by fetching the existing tuple; this package raises
 * an error to make the duplication explicit.
 */
export class DuplicateTupleError extends AuthzError {
  constructor(
    message: string,
    public readonly existingTupleId: string,
  ) {
    super(message, "conflict.duplicate_tuple");
    this.name = "DuplicateTupleError";
  }
}

/** An input violates a spec-defined format rule (e.g. relation name pattern). */
export class InvalidFormatError extends AuthzError {
  constructor(message: string, field: string) {
    super(message, `invalid_format.${field}`);
    this.name = "InvalidFormatError";
  }
}

/** The check-set form was called with an empty relations array. */
export class EmptyRelationSetError extends AuthzError {
  constructor() {
    super("check() relations array must be non-empty", "invalid_format.relations");
    this.name = "EmptyRelationSetError";
  }
}

/**
 * Rewrite-rule evaluation exceeded a configured bound (depth or fan-out).
 *
 * Bounds are configurable per-store; the spec floor is depth=8,
 * fan-out=1024. Apps hitting this in practice should restructure their
 * rule set or explicitly raise the limit.
 *
 * v0.2; see ADR 0007.
 */
export class EvaluationLimitExceededError extends AuthzError {
  constructor(message: string) {
    super(message, "evaluation_limit_exceeded");
    this.name = "EvaluationLimitExceededError";
  }
}

// ─── v0.2 share-token errors (ADR 0012) ───

/**
 * Generic violation of `verifyShareToken` precondition: token doesn't match
 * any row, or hash comparison failed. Deliberately conflated to avoid a
 * timing oracle distinguishing "no such hash" from "hash collision but
 * mismatch."
 */
export class InvalidShareTokenError extends AuthzError {
  constructor(message: string = "Invalid share token") {
    super(message, "invalid_share_token");
    this.name = "InvalidShareTokenError";
  }
}

/** The share's `expires_at` has passed. */
export class ShareExpiredError extends AuthzError {
  constructor(message: string = "Share has expired") {
    super(message, "share_expired");
    this.name = "ShareExpiredError";
  }
}

/** The share has been explicitly revoked. */
export class ShareRevokedError extends AuthzError {
  constructor(message: string = "Share has been revoked") {
    super(message, "share_revoked");
    this.name = "ShareRevokedError";
  }
}

/** A single-use share has already been consumed. */
export class ShareConsumedError extends AuthzError {
  constructor(message: string = "Share has already been consumed") {
    super(message, "share_consumed");
    this.name = "ShareConsumedError";
  }
}

/** A share with the requested id does not exist. */
export class ShareNotFoundError extends AuthzError {
  constructor(message: string) {
    super(message, "not_found");
    this.name = "ShareNotFoundError";
  }
}

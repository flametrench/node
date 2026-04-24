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

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

export class AuditError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

/**
 * A shape or value on the write input violated the ADR 0019 contract.
 *
 * `field` names the offending part of the event:
 *   - `"auth"` — zero, multiple, or mismatched auth kind/id fields
 *   - `"size"` — event exceeds the 64 KB limit
 *   - `"outcome"` — value outside {success, failure, denied, pending}
 *   - `"actor_usr_id"` — non-null but not a valid usr_<32hex>
 *   - `"target.kind"` — matches neither a Flametrench entity type nor ^[a-z]{2,6}$
 */
export class InvalidFormatError extends AuditError {
  constructor(
    readonly field: string,
    message: string,
  ) {
    super("INVALID_FORMAT", message);
  }
}

/**
 * A system-state precondition was not met (e.g. lookup against current state
 * returned an unexpected value). Distinct from InvalidFormatError, which covers
 * input-shape/value violations independently of system state.
 */
export class PreconditionError extends AuditError {
  constructor(message: string) {
    super("PRECONDITION", message);
  }
}

export class NotFoundError extends AuditError {
  constructor(message: string) {
    super("NOT_FOUND", message);
  }
}

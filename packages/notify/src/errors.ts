// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

export class NotifyError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

/**
 * A shape or value on the input violated the ADR 0022 contract.
 *
 * `field` names the offending field:
 *   - `"type"` — outside ^[a-z0-9._-]{1,64}$
 *   - `"data"` — not a JSON object, or > 16 KB
 *   - `"recipient_usr_id"` — not a valid usr_<32hex>
 *   - `"scope"` — not a valid org_<32hex>
 *   - `"subject"` — malformed (missing kind/id, wrong shape)
 */
export class InvalidFormatError extends NotifyError {
  constructor(
    readonly field: string,
    message: string,
  ) {
    super("INVALID_FORMAT", message);
  }
}

/**
 * A state-machine precondition was not met.
 * Thrown when attempting any transition out of the terminal `dismissed` state.
 */
export class PreconditionError extends NotifyError {
  constructor(message: string) {
    super("PRECONDITION", message);
  }
}

/**
 * The requested notification does not exist, or is not accessible to the caller.
 *
 * Per ADR 0022 recipient-scope / existence non-disclosure: a cross-recipient
 * or non-existent lookup raises the SAME error — no error-code differential
 * that could reveal a foreign notification's existence.
 */
export class NotFoundError extends NotifyError {
  constructor(message: string) {
    super("NOT_FOUND", message);
  }
}

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Base class for every identity-layer error. Carries a stable, machine-
 * readable `code` matching the OpenAPI Error envelope.
 */
export class IdentityError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = "IdentityError";
  }
}

export class NotFoundError extends IdentityError {
  constructor(message: string) {
    super(message, "not_found");
    this.name = "NotFoundError";
  }
}

/**
 * A credential with the same (type, identifier) already exists in an
 * active state. Per the spec, at most one active credential is permitted
 * per (type, identifier) pair; revoked historical credentials can share it.
 */
export class DuplicateCredentialError extends IdentityError {
  constructor(message: string) {
    super(message, "conflict.duplicate_credential");
    this.name = "DuplicateCredentialError";
  }
}

/** Password verification failed (wrong password, or no matching credential). */
export class InvalidCredentialError extends IdentityError {
  constructor(message: string) {
    super(message, "unauthorized.invalid_credential");
    this.name = "InvalidCredentialError";
  }
}

/** The referenced credential exists but is not active (suspended or revoked). */
export class CredentialNotActiveError extends IdentityError {
  constructor(message: string) {
    super(message, "conflict.credential_not_active");
    this.name = "CredentialNotActiveError";
  }
}

/** The session exists but has expired or been revoked. */
export class SessionExpiredError extends IdentityError {
  constructor(message: string) {
    super(message, "unauthorized.session_expired");
    this.name = "SessionExpiredError";
  }
}

/** The bearer token did not match any known session. */
export class InvalidTokenError extends IdentityError {
  constructor(message: string) {
    super(message, "unauthorized.invalid_token");
    this.name = "InvalidTokenError";
  }
}

/** The target entity is already in a terminal state. */
export class AlreadyTerminalError extends IdentityError {
  constructor(message: string) {
    super(message, "conflict.already_terminal");
    this.name = "AlreadyTerminalError";
  }
}

/** A request's preconditions were not met (generic guard). */
export class PreconditionError extends IdentityError {
  constructor(message: string, specifics: string) {
    super(message, `precondition.${specifics}`);
    this.name = "PreconditionError";
  }
}

/** Attempted to rotate a credential with a new payload of a different type. */
export class CredentialTypeMismatchError extends IdentityError {
  constructor(message: string) {
    super(message, "conflict.credential_type_mismatch");
    this.name = "CredentialTypeMismatchError";
  }
}

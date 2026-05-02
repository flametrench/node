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

/**
 * Raised by `verifyPatToken` when the bearer is malformed, references a
 * non-existent PAT row, OR carries the wrong secret (ADR 0016). The "no
 * such row" and "wrong secret" cases MUST conflate to this single error
 * class with an identical message — distinguishable errors leak
 * token-presence as a timing oracle.
 */
export class InvalidPatTokenError extends IdentityError {
  constructor(message: string = "invalid personal access token") {
    super(message, "pat.invalid");
    this.name = "InvalidPatTokenError";
  }
}

/**
 * Raised by `verifyPatToken` when the PAT row exists, has not been
 * revoked, but is past its `expiresAt` (ADR 0016).
 */
export class PatExpiredError extends IdentityError {
  constructor(patId: string) {
    super(`personal access token ${patId} is expired`, "pat.expired");
    this.name = "PatExpiredError";
  }
}

/**
 * Raised by `verifyPatToken` when the PAT row exists but has been
 * explicitly revoked via `revokePat` (ADR 0016). Terminal.
 */
export class PatRevokedError extends IdentityError {
  constructor(patId: string) {
    super(`personal access token ${patId} is revoked`, "pat.revoked");
    this.name = "PatRevokedError";
  }
}

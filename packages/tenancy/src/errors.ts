// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Base class for every tenancy-layer error. Carries a stable, machine-readable
 * `code` used by the OpenAPI error envelope; `message` is human-readable.
 *
 * Error codes follow a dot-namespaced convention: `<category>.<specifics>`.
 * Categories are stable across the lifetime of v0.1. Specifics may be added
 * without a version bump; they MUST NOT be renamed.
 */
export class TenancyError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = "TenancyError";
  }
}

/** The referenced entity does not exist. */
export class NotFoundError extends TenancyError {
  constructor(message: string) {
    super(message, "not_found");
    this.name = "NotFoundError";
  }
}

/**
 * Sole-owner protection was triggered: the requested operation would leave
 * the org without an active owner. Self-leave must supply `transferTo`;
 * admin-remove of the sole owner is impossible through `adminRemove` and
 * MUST go via `transferOwnership`.
 */
export class SoleOwnerError extends TenancyError {
  constructor(message: string) {
    super(message, "conflict.sole_owner");
    this.name = "SoleOwnerError";
  }
}

/**
 * The admin's role is not sufficient to remove (or otherwise modify) the
 * target's role. In the admin hierarchy `owner > admin > member > guest`,
 * admins can only remove members at or below their own level, and owners
 * can only be removed via ownership transfer.
 */
export class RoleHierarchyError extends TenancyError {
  constructor(message: string) {
    super(message, "forbidden.role_hierarchy");
    this.name = "RoleHierarchyError";
  }
}

/**
 * A membership already exists in the active state for the given (usr, org).
 * Duplicate active memberships are prohibited; revoked historical rows may
 * coexist for the same pair.
 */
export class DuplicateMembershipError extends TenancyError {
  constructor(message: string) {
    super(message, "conflict.duplicate_membership");
    this.name = "DuplicateMembershipError";
  }
}

/** The target entity is already in a terminal state; the transition is a no-op or invalid. */
export class AlreadyTerminalError extends TenancyError {
  constructor(message: string) {
    super(message, "conflict.already_terminal");
    this.name = "AlreadyTerminalError";
  }
}

/** The invitation's TTL has elapsed; acceptance is not allowed. */
export class InvitationExpiredError extends TenancyError {
  constructor(message: string) {
    super(message, "conflict.invitation_expired");
    this.name = "InvitationExpiredError";
  }
}

/** Attempted to change an invitation already in a terminal state. */
export class InvitationNotPendingError extends TenancyError {
  constructor(message: string) {
    super(message, "conflict.invitation_not_pending");
    this.name = "InvitationNotPendingError";
  }
}

/** The caller is not authorized to perform the operation. */
export class ForbiddenError extends TenancyError {
  constructor(message: string) {
    super(message, "forbidden");
    this.name = "ForbiddenError";
  }
}

/** The operation's preconditions were not met (generic guard). */
export class PreconditionError extends TenancyError {
  constructor(message: string, specifics: string) {
    super(message, `precondition.${specifics}`);
    this.name = "PreconditionError";
  }
}

/**
 * `acceptInvitation` was called with `asUsrId` but no `acceptingIdentifier`.
 *
 * Per ADR 0009, the SDK fails closed: callers MUST supply
 * `acceptingIdentifier` whenever they assert an existing `asUsrId`. The
 * mint-new-user path (`asUsrId` omitted) does not need this parameter.
 */
export class IdentifierBindingRequiredError extends PreconditionError {
  constructor(
    message = "acceptInvitation requires acceptingIdentifier when asUsrId is provided",
  ) {
    super(message, "identifier_binding_required");
    this.name = "IdentifierBindingRequiredError";
  }
}

/**
 * The supplied `acceptingIdentifier` does not match `invitation.identifier`.
 *
 * Per ADR 0009, this byte-equality check is the SDK's contribution to
 * closing the privilege-escalation primitive in spec#5: an attacker
 * substituting a foreign `usr_id` will fail to also produce a matching
 * identifier sourced from the authenticated session.
 */
export class IdentifierMismatchError extends PreconditionError {
  constructor(
    public readonly acceptingIdentifier: string,
    public readonly invitationIdentifier: string,
  ) {
    super(
      `acceptingIdentifier ${JSON.stringify(acceptingIdentifier)} does not match ` +
        `invitation.identifier ${JSON.stringify(invitationIdentifier)}`,
      "identifier_mismatch",
    );
    this.name = "IdentifierMismatchError";
  }
}

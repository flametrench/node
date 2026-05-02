// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import {
  AlreadyTerminalError as IdentityAlreadyTerminal,
  CredentialNotActiveError,
  CredentialTypeMismatchError,
  DuplicateCredentialError,
  IdentityError,
  InvalidCredentialError,
  InvalidPatTokenError,
  InvalidTokenError,
  NotFoundError as IdentityNotFound,
  PatExpiredError,
  PatRevokedError,
  PreconditionError as IdentityPrecondition,
  SessionExpiredError,
} from "@flametrench/identity";
import {
  InvalidShareTokenError,
  ShareConsumedError,
  ShareExpiredError,
  ShareRevokedError,
} from "@flametrench/authz";
import { TokenFormatUnrecognizedError } from "./resolve-bearer.js";
import {
  AlreadyTerminalError as TenancyAlreadyTerminal,
  DuplicateMembershipError,
  ForbiddenError,
  InvitationExpiredError,
  InvitationNotPendingError,
  NotFoundError as TenancyNotFound,
  PreconditionError as TenancyPrecondition,
  RoleHierarchyError,
  SoleOwnerError,
  TenancyError,
} from "@flametrench/tenancy";
import {
  AuthzError,
  DuplicateTupleError,
  EmptyRelationSetError,
  InvalidFormatError,
  TupleNotFoundError,
} from "@flametrench/authz";

/**
 * The wire-format error envelope returned for every non-2xx response.
 * Matches the OpenAPI v0.1 Error schema: stable machine-readable `code`,
 * human-readable `message`, optional `details` object.
 */
export interface ErrorEnvelope {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Translate any SDK-thrown error into an HTTP status code + envelope.
 *
 * The mapping is stable and documented in the OpenAPI spec so that
 * conforming clients can handle errors without string-matching.
 */
export function mapErrorToResponse(
  err: unknown,
): { status: number; envelope: ErrorEnvelope } {
  // ─── 404 Not Found ───
  if (err instanceof IdentityNotFound || err instanceof TenancyNotFound || err instanceof TupleNotFoundError) {
    return { status: 404, envelope: errEnv(err) };
  }

  // ─── 401 Unauthenticated ───
  if (
    err instanceof InvalidCredentialError ||
    err instanceof InvalidTokenError ||
    err instanceof SessionExpiredError ||
    // v0.3 PAT bearer rejections (security-audit H5).
    err instanceof InvalidPatTokenError ||
    err instanceof PatExpiredError ||
    err instanceof PatRevokedError ||
    // v0.3 share bearer rejections (already shipped in v0.2 but
    // weren't routed through this map until H5 wired them in).
    err instanceof InvalidShareTokenError ||
    err instanceof ShareExpiredError ||
    err instanceof ShareRevokedError ||
    err instanceof ShareConsumedError ||
    // Bearer prefix didn't match any wired verifier (e.g. shr_ with
    // no shareStore wired). Per ADR 0016 §"Bearer routing".
    err instanceof TokenFormatUnrecognizedError
  ) {
    return { status: 401, envelope: errEnv(err) };
  }

  // ─── 403 Forbidden ───
  if (err instanceof ForbiddenError || err instanceof RoleHierarchyError) {
    return { status: 403, envelope: errEnv(err) };
  }

  // ─── 409 Conflict ───
  if (
    err instanceof SoleOwnerError ||
    err instanceof DuplicateMembershipError ||
    err instanceof DuplicateCredentialError ||
    err instanceof DuplicateTupleError ||
    err instanceof IdentityAlreadyTerminal ||
    err instanceof TenancyAlreadyTerminal ||
    err instanceof InvitationExpiredError ||
    err instanceof InvitationNotPendingError ||
    err instanceof CredentialNotActiveError ||
    err instanceof CredentialTypeMismatchError ||
    err instanceof IdentityPrecondition ||
    err instanceof TenancyPrecondition
  ) {
    return { status: 409, envelope: errEnv(err) };
  }

  // ─── 400 Bad Request ───
  if (err instanceof InvalidFormatError || err instanceof EmptyRelationSetError) {
    return { status: 400, envelope: errEnv(err) };
  }

  // ─── Other SDK errors → 400 with their code ───
  if (err instanceof IdentityError || err instanceof TenancyError || err instanceof AuthzError) {
    return { status: 400, envelope: errEnv(err) };
  }

  // ─── Unknown → 500 ───
  const message = err instanceof Error ? err.message : String(err);
  return {
    status: 500,
    envelope: { code: "internal_error", message },
  };
}

function errEnv(err: { code: string; message: string }): ErrorEnvelope {
  return { code: err.code, message: err.message };
}

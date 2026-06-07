// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/audit — append-only, identity- and tenancy-aware action logging.
 *
 * See the normative specification at spec/decisions/0019-audit-primitive.md.
 *
 * This package exports:
 *
 *   - Entity types that match the wire contract.
 *   - An AuditStore interface — the contract every backend fulfills.
 *   - An InMemoryAuditStore implementation — reference / tests.
 *   - Error classes with spec-stable `code` identifiers.
 */

export type {
  AuditAuth,
  AuditContext,
  AuditEvent,
  AuditId,
  AuditOnBehalf,
  AuditScope,
  AuditTarget,
  AuthKind,
  Outcome,
  UsrId,
  WriteAuditInput,
} from "./types.js";

export type { AuditStore } from "./store.js";

export { InMemoryAuditStore } from "./in-memory.js";

export { AuditError, InvalidFormatError, NotFoundError, PreconditionError } from "./errors.js";

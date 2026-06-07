// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { AuditEvent, AuditId, WriteAuditInput } from "./types.js";

/**
 * The AuditStore interface is the contract every audit backend fulfills.
 *
 * Audit events are append-only and immutable once written. No update or
 * delete operations exist per ADR 0019.
 *
 * `write` MUST be durable before it returns — audit is fail-closed.
 */
export interface AuditStore {
  /** Append a durable, immutable audit event. Returns the stored event (including server-set id and recordedAt). */
  write(input: WriteAuditInput): Promise<AuditEvent>;

  /** Fetch an event by id. Throws NotFoundError if not found. */
  get(id: AuditId): Promise<AuditEvent>;
}

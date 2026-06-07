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
 *
 * **Cursor / ordering non-disclosure (ADR 0019 #46).**
 * Any future `query`/`count`/`export` operation that accepts a scope filter
 * MUST NOT expose a global or cross-scope sequence position through cursors,
 * counts, or `id` ordering. Cursors MUST be opaque per-scope positions
 * (over `(recorded_at, id)` within that scope); a global monotonic counter
 * MUST NOT be encoded into a scoped cursor in a gap-observable form. A
 * UUIDv7 monotonic sub-counter used for `id` generation MUST be per-scope
 * or random — never a shared global counter that two same-millisecond events
 * in different scopes could reveal to each other via an id gap.
 */
export interface AuditStore {
  /** Append a durable, immutable audit event. Returns the stored event (including server-set id and recordedAt). */
  write(input: WriteAuditInput): Promise<AuditEvent>;

  /** Fetch an event by id. Throws NotFoundError if not found. */
  get(id: AuditId): Promise<AuditEvent>;
}

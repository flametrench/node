// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/notify — per-recipient, read-stateful notification records.
 *
 * Record/event primitive — NOT a delivery engine. See ADR 0022.
 *
 * Exports:
 *   - Entity types matching the wire contract.
 *   - A NotifyStore interface — the contract every backend fulfills.
 *   - An InMemoryNotifyStore implementation — reference / tests.
 *   - Error classes with spec-stable `code` identifiers.
 */

export type {
  CreateNotificationInput,
  NotId,
  Notification,
  NotificationState,
  NotificationSubject,
  OrgId,
  UsrId,
} from "./types.js";

export type { NotifyStore } from "./store.js";

export { InMemoryNotifyStore } from "./in-memory.js";

export { InvalidFormatError, NotFoundError, NotifyError, PreconditionError } from "./errors.js";

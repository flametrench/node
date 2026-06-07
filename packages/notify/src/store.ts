// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { CreateNotificationInput, Notification, NotId, UsrId } from "./types.js";

/**
 * The NotifyStore interface is the contract every notifications backend fulfills.
 *
 * Access is **strictly recipient-scoped, SDK-enforced** (ADR 0022 Option 2):
 * every per-notification operation takes the authenticated `recipientUsrId`
 * and MUST constrain the lookup to it — no cross-recipient read path exists.
 *
 * Non-inference: any operation targeting a notification that does not exist
 * OR belongs to a different recipient MUST raise the same `NotFoundError` —
 * no presence/error-code differential. Ownership check resolves BEFORE any
 * `PreconditionError` to prevent state leakage (e.g. a `dismiss` on a foreign
 * already-dismissed notification → `NotFoundError`, not `PreconditionError`).
 */
export interface NotifyStore {
  createNotification(input: CreateNotificationInput): Promise<Notification>;
  getNotification(id: NotId, recipientUsrId: UsrId): Promise<Notification>;
  markRead(id: NotId, recipientUsrId: UsrId): Promise<Notification>;
  markUnread(id: NotId, recipientUsrId: UsrId): Promise<Notification>;
  dismiss(id: NotId, recipientUsrId: UsrId): Promise<Notification>;
  countUnread(recipientUsrId: UsrId, scope: string): Promise<number>;
}

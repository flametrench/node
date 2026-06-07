// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { CreateNotificationInput, Notification, NotId } from "./types.js";

/**
 * The NotifyStore interface is the contract every notifications backend fulfills.
 *
 * Access is strictly recipient-scoped: all operations on a notification
 * are bound to the notification's `recipientUsrId`. This primitive exposes
 * only the recipient's own inbox — no cross-recipient read path exists.
 *
 * Non-inference: `get`/`markRead`/`markUnread`/`dismiss` targeting a
 * notification that does not exist OR belongs to a different recipient MUST
 * raise the same `NotFoundError` — no presence/error-code differential.
 */
export interface NotifyStore {
  createNotification(input: CreateNotificationInput): Promise<Notification>;
  getNotification(id: NotId): Promise<Notification>;
  markRead(id: NotId): Promise<Notification>;
  markUnread(id: NotId): Promise<Notification>;
  dismiss(id: NotId): Promise<Notification>;
}

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Flametrench v0.4 notification entity types (ADR 0022).
 *
 * Field names are camelCase; timestamps are native Date objects.
 * Wire serialization (snake_case, ISO strings) happens at the
 * server/client boundary, not here.
 */

export type NotId = `not_${string}`;
export type OrgId = `org_${string}`;
export type UsrId = `usr_${string}`;

/** The three lifecycle states of a notification. `dismissed` is terminal. */
export type NotificationState = "unread" | "read" | "dismissed";

/** What the notification is about. */
export interface NotificationSubject {
  kind: string;
  id: string;
}

/** A durable, per-recipient notification record. */
export interface Notification {
  id: NotId;
  /** The org scope this notification belongs to. */
  scope: OrgId;
  /** The user this notification is addressed to. */
  recipientUsrId: UsrId;
  /** Adopter-namespaced kind, opaque to the primitive. ^[a-z0-9._-]{1,64}$ */
  type: string;
  /** What the notification is about; Flametrench id OR opaque adopter id. */
  subject: NotificationSubject;
  /** Free-form record content for the adopter's rendering. ≤ 16 KB. NOT a template. */
  data: Record<string, unknown>;
  state: NotificationState;
  createdAt: Date;
  /** Updated on each state transition. */
  stateChangedAt: Date;
}

/** Input to NotifyStore.createNotification(). */
export interface CreateNotificationInput {
  scope: OrgId;
  recipientUsrId: UsrId;
  type: string;
  subject: NotificationSubject;
  data: Record<string, unknown>;
}

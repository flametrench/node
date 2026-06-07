// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate, isValid } from "@flametrench/ids";

import { InvalidFormatError, NotFoundError, PreconditionError } from "./errors.js";
import type { NotifyStore } from "./store.js";
import type {
  CreateNotificationInput,
  Notification,
  NotId,
  NotificationState,
  OrgId,
  UsrId,
} from "./types.js";

const TYPE_PATTERN = /^[a-z0-9._-]{1,64}$/;
const DATA_SIZE_LIMIT = 16 * 1024; // 16 KB

function validateCreate(input: CreateNotificationInput): void {
  if (!isValid(input.scope, "org")) {
    throw new InvalidFormatError("scope", `scope must be a valid org_<32hex>, got: ${String(input.scope)}`);
  }
  if (!isValid(input.recipientUsrId, "usr")) {
    throw new InvalidFormatError("recipient_usr_id", `recipient_usr_id must be a valid usr_<32hex>, got: ${String(input.recipientUsrId)}`);
  }
  if (!TYPE_PATTERN.test(input.type)) {
    throw new InvalidFormatError("type", `type must match ^[a-z0-9._-]{1,64}$, got: ${JSON.stringify(input.type)}`);
  }
  if (
    input.subject === null ||
    typeof input.subject !== "object" ||
    typeof input.subject.kind !== "string" ||
    input.subject.kind.length === 0 ||
    typeof input.subject.id !== "string" ||
    input.subject.id.length === 0
  ) {
    throw new InvalidFormatError("subject", `subject must have non-empty string kind and id`);
  }
  if (input.data === null || typeof input.data !== "object" || Array.isArray(input.data)) {
    throw new InvalidFormatError("data", `data must be a JSON object`);
  }
  if (Buffer.byteLength(JSON.stringify(input.data), "utf8") > DATA_SIZE_LIMIT) {
    throw new InvalidFormatError("data", `data exceeds the 16 KB limit`);
  }
}

/**
 * Reference in-memory implementation of NotifyStore (ADR 0022, Option 2).
 *
 * Suitable for tests and in-memory prototyping. Not durable across
 * process restarts.
 *
 * Recipient-scope / existence non-disclosure (SDK-enforced):
 * - All lookup ops take `recipientUsrId` and scope internally.
 * - `getOrThrow` raises `NotFoundError` for both missing AND cross-recipient
 *   notifications — no presence/error-code differential.
 * - Ownership check resolves BEFORE state-machine validation (PreconditionError)
 *   so a foreign already-dismissed notification raises `NotFoundError`,
 *   not `PreconditionError`.
 */
export class InMemoryNotifyStore implements NotifyStore {
  private readonly notifications = new Map<NotId, Notification>();

  async createNotification(input: CreateNotificationInput): Promise<Notification> {
    validateCreate(input);
    const id = generate("not") as NotId;
    const now = new Date();
    const notification: Notification = {
      id,
      scope: input.scope as OrgId,
      recipientUsrId: input.recipientUsrId as UsrId,
      type: input.type,
      subject: { ...input.subject },
      data: { ...input.data },
      state: "unread",
      createdAt: now,
      stateChangedAt: now,
    };
    this.notifications.set(id, notification);
    return notification;
  }

  async getNotification(id: NotId, recipientUsrId: UsrId): Promise<Notification> {
    return this.getOrThrow(id, recipientUsrId);
  }

  async markRead(id: NotId, recipientUsrId: UsrId): Promise<Notification> {
    // Ownership check (→ NotFoundError) BEFORE state check (→ PreconditionError).
    const n = this.getOrThrow(id, recipientUsrId);
    if (n.state === "dismissed") {
      throw new PreconditionError(`Cannot transition a dismissed notification (id: ${id})`);
    }
    const updated: Notification = { ...n, state: "read", stateChangedAt: new Date() };
    this.notifications.set(id, updated);
    return updated;
  }

  async markUnread(id: NotId, recipientUsrId: UsrId): Promise<Notification> {
    const n = this.getOrThrow(id, recipientUsrId);
    if (n.state === "dismissed") {
      throw new PreconditionError(`Cannot transition a dismissed notification (id: ${id})`);
    }
    const updated: Notification = { ...n, state: "unread", stateChangedAt: new Date() };
    this.notifications.set(id, updated);
    return updated;
  }

  async dismiss(id: NotId, recipientUsrId: UsrId): Promise<Notification> {
    const n = this.getOrThrow(id, recipientUsrId);
    if (n.state === "dismissed") {
      throw new PreconditionError(`Cannot transition a dismissed notification (id: ${id})`);
    }
    const updated: Notification = { ...n, state: "dismissed", stateChangedAt: new Date() };
    this.notifications.set(id, updated);
    return updated;
  }

  async countUnread(recipientUsrId: UsrId, scope: string): Promise<number> {
    let count = 0;
    for (const n of this.notifications.values()) {
      if (n.recipientUsrId === recipientUsrId && n.scope === scope && (n.state as NotificationState) === "unread") {
        count++;
      }
    }
    return count;
  }

  private getOrThrow(id: NotId, recipientUsrId: UsrId): Notification {
    const n = this.notifications.get(id);
    // Treat missing and cross-recipient identically — no existence differential.
    if (!n || n.recipientUsrId !== recipientUsrId) {
      throw new NotFoundError(`Notification not found: ${id}`);
    }
    return n;
  }
}

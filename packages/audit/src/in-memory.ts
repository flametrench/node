// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate } from "@flametrench/ids";

import { NotFoundError } from "./errors.js";
import type { AuditStore } from "./store.js";
import type { AuditEvent, AuditId, WriteAuditInput } from "./types.js";

/**
 * Reference in-memory implementation of AuditStore (ADR 0019).
 *
 * Suitable for tests and in-memory prototyping. Not durable across
 * process restarts. Append-only: no update or delete.
 */
export class InMemoryAuditStore implements AuditStore {
  private readonly events = new Map<AuditId, AuditEvent>();

  async write(input: WriteAuditInput): Promise<AuditEvent> {
    const id = generate("aud") as AuditId;
    const recordedAt = new Date();

    const event: AuditEvent = {
      id,
      occurredAt: input.occurredAt,
      recordedAt,
      actorUsrId: input.actorUsrId,
      action: input.action,
      target: { ...input.target },
      outcome: input.outcome,
      metadata: { ...input.metadata },
    };

    if (input.auth !== undefined) {
      event.auth = { ...input.auth };
    }
    if (input.onBehalf !== undefined) {
      event.onBehalf = { ...input.onBehalf };
    }
    if (input.scope !== undefined) {
      event.scope = { ...input.scope };
    }
    if (input.context !== undefined) {
      event.context = { ...input.context };
    }

    this.events.set(id, event);
    return event;
  }

  async get(id: AuditId): Promise<AuditEvent> {
    const event = this.events.get(id);
    if (!event) {
      throw new NotFoundError(`Audit event not found: ${id}`);
    }
    return event;
  }
}

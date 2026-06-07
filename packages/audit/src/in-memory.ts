// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate, isValid } from "@flametrench/ids";

import { InvalidFormatError, NotFoundError } from "./errors.js";
import type { AuditStore } from "./store.js";
import type { AuditAuth, AuditEvent, AuditId, Outcome, WriteAuditInput } from "./types.js";

const VALID_OUTCOMES = new Set<Outcome>(["success", "failure", "denied", "pending"]);
// ADR 0019: target.kind must be a Flametrench entity type OR adopter ^[a-z]{2,6}$
// All registered Flametrench prefixes already satisfy ^[a-z]{2,6}$, so a single
// pattern covers both populations.
const TARGET_KIND_PATTERN = /^[a-z]{2,6}$/;
const AUTH_KIND_TO_FIELD = {
  session: "sessionId",
  pat: "patId",
  share: "shareId",
  system: "systemId",
} as const satisfies Record<AuditAuth["kind"], keyof AuditAuth>;
const EVENT_SIZE_LIMIT = 64 * 1024; // 64 KB

function validateWrite(input: WriteAuditInput): void {
  // outcome
  if (!VALID_OUTCOMES.has(input.outcome)) {
    throw new InvalidFormatError("outcome", `outcome must be one of success|failure|denied|pending, got: ${String(input.outcome)}`);
  }

  // actor_usr_id — null is valid (pre-auth/system); non-null must be usr_<32hex>
  if (input.actorUsrId !== null && !isValid(input.actorUsrId, "usr")) {
    throw new InvalidFormatError("actor_usr_id", `actor_usr_id must be null or a valid usr_<32hex>, got: ${String(input.actorUsrId)}`);
  }

  // target.kind — Flametrench entity type or adopter ^[a-z]{2,6}$
  if (!TARGET_KIND_PATTERN.test(input.target.kind)) {
    throw new InvalidFormatError("target.kind", `target.kind must match ^[a-z]{2,6}$, got: ${JSON.stringify(input.target.kind)}`);
  }

  // auth — exactly one kind-specific id field, matching kind
  if (input.auth !== undefined) {
    const { kind, sessionId, patId, shareId, systemId } = input.auth;
    const expectedField = AUTH_KIND_TO_FIELD[kind];
    const kindFields = { sessionId, patId, shareId, systemId };
    const presentFields = Object.entries(kindFields).filter(([, v]) => v !== undefined).map(([k]) => k);
    if (presentFields.length !== 1 || presentFields[0] !== expectedField) {
      throw new InvalidFormatError(
        "auth",
        `auth.kind=${kind} requires exactly auth.${expectedField}; found: [${presentFields.join(", ") || "none"}]`,
      );
    }
  }

  // size — whole event (including metadata) must be ≤ 64 KB
  const json = JSON.stringify(input);
  if (Buffer.byteLength(json, "utf8") > EVENT_SIZE_LIMIT) {
    throw new InvalidFormatError("size", `Event exceeds the 64 KB size limit`);
  }
}

/**
 * Reference in-memory implementation of AuditStore (ADR 0019).
 *
 * Suitable for tests and in-memory prototyping. Not durable across
 * process restarts. Append-only: no update or delete.
 */
export class InMemoryAuditStore implements AuditStore {
  private readonly events = new Map<AuditId, AuditEvent>();

  async write(input: WriteAuditInput): Promise<AuditEvent> {
    validateWrite(input);
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

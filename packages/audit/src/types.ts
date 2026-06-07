// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Flametrench v0.4 audit entity types (ADR 0019).
 *
 * Field names are camelCase; timestamps are native Date objects.
 * Wire serialization (snake_case, ISO strings) happens at the server/client
 * boundary, not here.
 */

export type AuditId = `aud_${string}`;
export type UsrId = `usr_${string}`;

/** ADR 0016 frozen vocabulary, fulfilled by ADR 0019. */
export type AuthKind = "session" | "pat" | "share" | "system";

/** The credential context under which the action was performed. Optional — absent for pre-auth/anonymous events. */
export interface AuditAuth {
  kind: AuthKind;
  /** Present IFF kind = "session". */
  sessionId?: `ses_${string}`;
  /** Present IFF kind = "pat". */
  patId?: `pat_${string}`;
  /** Present IFF kind = "share". */
  shareId?: `shr_${string}`;
  /** Present IFF kind = "system" — opaque, adopter-defined. */
  systemId?: string;
}

/** A delegated non-human actor (orthogonal to auth.kind). */
export interface AuditOnBehalf {
  agentId: string;
}

/** The entity the action was performed on. */
export interface AuditTarget {
  kind: string;
  id: string;
}

/** The tenancy boundary the action occurred within. Optional — absent for global/system events. */
export interface AuditScope {
  kind: string;
  id: string;
}

/** Optional request context. */
export interface AuditContext {
  requestId?: string;
  ip?: string;
  userAgent?: string;
}

export type Outcome = "success" | "failure" | "denied" | "pending";

/** A durable, immutable audit event. */
export interface AuditEvent {
  id: AuditId;
  /** Emitter clock — when the action occurred. */
  occurredAt: Date;
  /** Server-authoritative — when the audit service durably recorded the event. */
  recordedAt: Date;
  actorUsrId: UsrId | null;
  /** Absent when there is no established principal (pre-auth, anonymous, failed login). */
  auth?: AuditAuth;
  /** Present IFF a delegated non-human actor performed the action. */
  onBehalf?: AuditOnBehalf;
  action: string;
  target: AuditTarget;
  /** Absent for global / non-org-scoped events. */
  scope?: AuditScope;
  outcome: Outcome;
  metadata: Record<string, unknown>;
  context?: AuditContext;
}

/** Input to AuditStore.write(). Excludes server-set fields (id, recordedAt). */
export interface WriteAuditInput {
  occurredAt: Date;
  actorUsrId: UsrId | null;
  auth?: AuditAuth;
  onBehalf?: AuditOnBehalf;
  action: string;
  target: AuditTarget;
  scope?: AuditScope;
  outcome: Outcome;
  metadata: Record<string, unknown>;
  context?: AuditContext;
}

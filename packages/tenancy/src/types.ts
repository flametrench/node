// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Flametrench v0.1 tenancy entity types.
 *
 * These mirror the normative shapes in spec/docs/tenancy.md and
 * spec/openapi/flametrench-v0.1.yaml, with two idiomatic JS/TS adaptations:
 *
 *   - Field names are camelCase (e.g. `createdAt`). On the wire the spec uses
 *     snake_case; that conversion happens at the server/client boundary, not
 *     here in the SDK core.
 *   - Timestamps are native `Date` objects, not ISO strings. Stringification
 *     (or Postgres TIMESTAMPTZ rendering) also happens at the boundary.
 *
 * ID fields are typed as template-literal strings (`org_${string}` etc.).
 * This gives type safety without runtime cost; malformed inputs are still
 * caught at runtime by @flametrench/ids decode/validation.
 */

export type OrgId = `org_${string}`;
export type UsrId = `usr_${string}`;
export type MemId = `mem_${string}`;
export type InvId = `inv_${string}`;

/**
 * The six built-in relations for v0.1. Applications may register custom
 * relations (any string matching /^[a-z_]{2,32}$/); they are typed as
 * `string` when used as custom-relation values. The spec-registered set is
 * narrowed via this literal union for compile-time autocomplete and safety.
 */
export type Role = "owner" | "admin" | "member" | "guest" | "viewer" | "editor";

/**
 * The role-hierarchy subset used by the admin-remove precondition.
 * `viewer` and `editor` are resource-scoped and do not participate.
 */
export const ADMIN_HIERARCHY = ["owner", "admin", "member", "guest"] as const;
export type AdminHierarchyRole = (typeof ADMIN_HIERARCHY)[number];

/** Lifecycle status shared by orgs, memberships, and credentials. */
export type Status = "active" | "suspended" | "revoked";

/** Invitation state machine. `pending` is the only non-terminal value. */
export type InvitationStatus =
  | "pending"
  | "accepted"
  | "declined"
  | "revoked"
  | "expired";

// ─── Entities ───

export interface Organization {
  id: OrgId;
  status: Status;
  createdAt: Date;
  updatedAt: Date;
}

export interface Membership {
  id: MemId;
  usrId: UsrId;
  orgId: OrgId;
  role: Role;
  status: Status;
  /** Previous membership in the rotation chain; null at the chain root. */
  replaces: MemId | null;
  /** User who initiated the invitation; null for the org-creator bootstrap. */
  invitedBy: UsrId | null;
  /**
   * User who removed this membership. `null` for self-leave; non-null for
   * admin-remove. Telltale field for audit attribution per ADR 0002.
   */
  removedBy: UsrId | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface PreTuple {
  relation: string;
  objectType: string;
  objectId: string;
}

export interface Invitation {
  id: InvId;
  orgId: OrgId;
  /** The invitee identifier (typically email). */
  identifier: string;
  role: Role;
  status: InvitationStatus;
  /** Resource-scoped grants to materialize on accept. Possibly empty. */
  preTuples: PreTuple[];
  invitedBy: UsrId;
  /** Resolved at accept time. */
  invitedUserId: UsrId | null;
  createdAt: Date;
  expiresAt: Date;
  /** Set when status leaves `pending`. */
  terminalAt: Date | null;
  /** Actor who caused the terminal transition; null for system-driven expiry. */
  terminalBy: UsrId | null;
}

/**
 * An authorization tuple. In v0.1, `subjectType` is always `"usr"`;
 * `objectType` is unconstrained so applications may tup custom object types
 * like `"project"` or `"doc"`.
 */
export interface Tuple {
  subjectType: "usr";
  subjectId: UsrId;
  relation: string;
  objectType: string;
  objectId: string;
}

// ─── Operation inputs ───

export interface AddMemberInput {
  orgId: OrgId;
  usrId: UsrId;
  role: Role;
  invitedBy?: UsrId | null;
}

export interface ChangeRoleInput {
  memId: MemId;
  newRole: Role;
}

export interface SelfLeaveInput {
  memId: MemId;
  /** Required iff the leaver is the sole active owner of the org. */
  transferTo?: UsrId;
}

export interface AdminRemoveInput {
  memId: MemId;
  adminUsrId: UsrId;
}

export interface TransferOwnershipInput {
  orgId: OrgId;
  fromMemId: MemId;
  toMemId: MemId;
}

export interface CreateInvitationInput {
  orgId: OrgId;
  identifier: string;
  role: Role;
  invitedBy: UsrId;
  expiresAt: Date;
  preTuples?: PreTuple[];
}

export interface AcceptInvitationInput {
  invId: InvId;
  /** If the invitee already has an account, pass their `usr_` id. */
  asUsrId?: UsrId;
}

export interface AcceptInvitationResult {
  invitation: Invitation;
  membership: Membership;
  /** Tuples created from `invitation.preTuples`. */
  materializedTuples: Tuple[];
}

export interface DeclineInvitationInput {
  invId: InvId;
  /** Invitee's usr_id if known; null for anonymous decline. */
  asUsrId?: UsrId | null;
}

export interface RevokeInvitationInput {
  invId: InvId;
  adminUsrId: UsrId;
}

export interface ListMembersOptions {
  cursor?: string;
  limit?: number;
  status?: Status;
}

export interface ListInvitationsOptions {
  cursor?: string;
  limit?: number;
  status?: InvitationStatus;
}

export interface Page<T> {
  data: T[];
  /** Opaque cursor for the next page; null when exhausted. */
  nextCursor: string | null;
}

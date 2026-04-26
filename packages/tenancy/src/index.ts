// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/tenancy — organizations, memberships, invitations.
 *
 * See the normative specification at spec/docs/tenancy.md, the design
 * decisions at spec/decisions/0002-tenancy-model.md and
 * spec/decisions/0003-invitation-state-machine.md, and the reference
 * Postgres schema at spec/reference/postgres.sql.
 *
 * This package exports:
 *
 *   - Entity types that match the wire contract.
 *   - A TenancyStore interface — the contract every backend fulfills.
 *   - An InMemoryTenancyStore implementation — reference / tests.
 *   - Error classes with spec-stable `code` identifiers.
 *
 * A Postgres-backed store lives in a separate entry point (to land in a
 * future release) so applications that don't need a database (tests,
 * in-memory prototyping, documentation) do not pay for a Postgres
 * dependency transitively.
 */

export type {
  AcceptInvitationInput,
  AcceptInvitationResult,
  AddMemberInput,
  AdminRemoveInput,
  ChangeRoleInput,
  CreateInvitationInput,
  CreateOrgInput,
  DeclineInvitationInput,
  InvId,
  Invitation,
  InvitationStatus,
  ListInvitationsOptions,
  ListMembersOptions,
  MemId,
  Membership,
  Organization,
  OrgId,
  Page,
  PreTuple,
  RevokeInvitationInput,
  Role,
  SelfLeaveInput,
  Status,
  TransferOwnershipInput,
  Tuple,
  UpdateOrgInput,
  UsrId,
} from "./types.js";
export { ADMIN_HIERARCHY } from "./types.js";

export type { TenancyStore } from "./store.js";

export {
  InMemoryTenancyStore,
  type InMemoryTenancyStoreOptions,
} from "./in-memory.js";

export {
  AlreadyTerminalError,
  DuplicateMembershipError,
  ForbiddenError,
  IdentifierBindingRequiredError,
  IdentifierMismatchError,
  InvitationExpiredError,
  InvitationNotPendingError,
  NotFoundError,
  OrgSlugConflictError,
  PreconditionError,
  RoleHierarchyError,
  SoleOwnerError,
  TenancyError,
} from "./errors.js";

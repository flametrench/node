// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type {
  AcceptInvitationInput,
  AcceptInvitationResult,
  AddMemberInput,
  AdminRemoveInput,
  ChangeRoleInput,
  CreateInvitationInput,
  CreateOrgInput,
  DeclineInvitationInput,
  Invitation,
  InvId,
  ListInvitationsOptions,
  ListMembersOptions,
  MemId,
  Membership,
  Organization,
  OrgId,
  Page,
  RevokeInvitationInput,
  SelfLeaveInput,
  TransferOwnershipInput,
  Tuple,
  UpdateOrgInput,
  UsrId,
} from "./types.js";

/**
 * The `TenancyStore` interface is the contract every tenancy backend fulfills.
 *
 * A "backend" is whatever durable storage implements these operations —
 * Postgres (the reference implementation in the spec), an in-memory map for
 * tests, a future Dynamo/SQLite/etc. adapter. The contract is what every
 * implementation must satisfy to be spec-conformant.
 *
 * **Atomicity guarantees.** Every operation that modifies more than one row
 * MUST be transactional. In particular:
 *
 *   - `changeRole` updates the old `mem_`, inserts a new `mem_`, deletes the
 *     old `tup_`, and inserts a new `tup_` — all in one transaction.
 *   - `acceptInvitation` creates a user if needed, inserts `mem_`, inserts
 *     the membership `tup_`, expands `preTuples` into additional `tup_`
 *     rows, and transitions the invitation — all in one transaction.
 *   - `transferOwnership` revokes the current owner's `mem_`, inserts a new
 *     owner `mem_` for the target, updates the recipient's previous `mem_`
 *     if it existed — all in one transaction.
 *
 * **Tuple duality.** The spec requires that every `mem_.status = active` has
 * a corresponding `tup_(usr, role, org)` row, and that the two are created,
 * updated, and removed together. An implementation that cannot guarantee
 * this is not conformant.
 */
export interface TenancyStore {
  // ─── Organizations ───

  /**
   * Create an org AND the creator's owner membership in one transaction.
   * Returns both so callers have both IDs without a round-trip.
   *
   * Accepts the v0.2 (ADR 0011) optional `name` and `slug` fields. Pass
   * a {@link CreateOrgInput} object for the v0.2 form, or just a
   * `UsrId` for the v0.1-compatible form.
   */
  createOrg(
    input: UsrId | CreateOrgInput,
  ): Promise<{ org: Organization; ownerMembership: Membership }>;
  getOrg(orgId: OrgId): Promise<Organization>;
  /**
   * v0.2 (ADR 0011) — partial update of `name` and/or `slug`. An
   * OMITTED field means "don't change"; an explicit `null` means
   * "set to null." Slug uniqueness violations raise OrgSlugConflictError;
   * updating a revoked org raises AlreadyTerminalError.
   */
  updateOrg(input: UpdateOrgInput): Promise<Organization>;
  suspendOrg(orgId: OrgId): Promise<Organization>;
  reinstateOrg(orgId: OrgId): Promise<Organization>;
  revokeOrg(orgId: OrgId): Promise<Organization>;

  // ─── Memberships ───

  addMember(input: AddMemberInput): Promise<Membership>;
  getMembership(memId: MemId): Promise<Membership>;
  listMembers(orgId: OrgId, options?: ListMembersOptions): Promise<Page<Membership>>;

  /** Revoke + re-add with `replaces` chain. Returns the new active membership. */
  changeRole(input: ChangeRoleInput): Promise<Membership>;

  suspendMembership(memId: MemId): Promise<Membership>;
  reinstateMembership(memId: MemId): Promise<Membership>;

  selfLeave(input: SelfLeaveInput): Promise<Membership>;
  adminRemove(input: AdminRemoveInput): Promise<Membership>;

  transferOwnership(input: TransferOwnershipInput): Promise<{
    fromMembership: Membership;
    toMembership: Membership;
  }>;

  // ─── Invitations ───

  createInvitation(input: CreateInvitationInput): Promise<Invitation>;
  getInvitation(invId: InvId): Promise<Invitation>;
  listInvitations(
    orgId: OrgId,
    options?: ListInvitationsOptions,
  ): Promise<Page<Invitation>>;

  acceptInvitation(input: AcceptInvitationInput): Promise<AcceptInvitationResult>;
  declineInvitation(input: DeclineInvitationInput): Promise<Invitation>;
  revokeInvitation(input: RevokeInvitationInput): Promise<Invitation>;

  // ─── Authorization tuple accessors (read-only) ───

  /**
   * Enumerate tuples with the given subject. Used by the future authz layer
   * to answer "what does Alice hold?" queries, and by test harnesses to
   * assert tuple materialization.
   */
  listTuplesForSubject(subjectType: "usr", subjectId: UsrId): Promise<Tuple[]>;

  /**
   * Enumerate tuples with the given object (and optionally relation). Used
   * to answer "who holds X on this object?" queries.
   */
  listTuplesForObject(
    objectType: string,
    objectId: string,
    relation?: string,
  ): Promise<Tuple[]>;
}

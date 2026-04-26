// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate } from "@flametrench/ids";

import {
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
} from "./errors.js";
import type { TenancyStore } from "./store.js";
import type {
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
  ListInvitationsOptions,
  ListMembersOptions,
  MemId,
  Membership,
  Organization,
  OrgId,
  Page,
  PreTuple,
  RevokeInvitationInput,
  SelfLeaveInput,
  Status,
  TransferOwnershipInput,
  Tuple,
  UpdateOrgInput,
  UsrId,
} from "./types.js";

// ADR 0011: DNS-label-style slug pattern (1-63 lowercase ASCII chars +
// digits + hyphens, no leading/trailing hyphen).
const SLUG_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

function validateSlug(slug: string): void {
  if (!SLUG_PATTERN.test(slug)) {
    throw new PreconditionError(
      `Slug ${JSON.stringify(slug)} does not match the spec pattern ` +
        `(DNS-label-style: 1-63 lowercase ASCII chars or digits or hyphens, ` +
        `no leading/trailing hyphen)`,
      "org_slug_format",
    );
  }
}

// ─── Admin hierarchy (for adminRemove precondition) ───
const ADMIN_RANK: Record<string, number> = {
  owner: 4,
  admin: 3,
  member: 2,
  guest: 1,
  // viewer/editor are resource-scoped and do not participate.
};

/**
 * Options for InMemoryTenancyStore construction.
 */
export interface InMemoryTenancyStoreOptions {
  /** Override the clock for deterministic tests. Default `() => new Date()`. */
  clock?: () => Date;
}

/**
 * An in-memory reference implementation of TenancyStore. Every state
 * transition is spec-conformant: revoke-and-re-add for role changes, atomic
 * acceptance for invitations, sole-owner protection on both self-leave and
 * admin-remove paths, and an internal tuple shadow-set maintained in lockstep
 * with membership lifecycle so the mem_/tup_ duality cannot drift.
 *
 * This implementation is intended for tests, documentation, and as the
 * canonical reference against which the Postgres-backed store's behavior is
 * measured. It does not persist across process restarts and is not safe for
 * concurrent access from multiple event loops.
 */
export class InMemoryTenancyStore implements TenancyStore {
  private readonly orgs = new Map<OrgId, Organization>();
  private readonly memberships = new Map<MemId, Membership>();
  private readonly invitations = new Map<InvId, Invitation>();
  /** Shadow set of active tuple keys; kept in sync with mem.status === 'active'. */
  private readonly tupleKeys = new Set<string>();
  private readonly clock: () => Date;

  constructor(options: InMemoryTenancyStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
  }

  // ─── Internal helpers ───

  private now(): Date {
    return this.clock();
  }

  private newOrgId(): OrgId {
    return generate("org") as OrgId;
  }
  private newMemId(): MemId {
    return generate("mem") as MemId;
  }
  private newInvId(): InvId {
    return generate("inv") as InvId;
  }
  private newUsrId(): UsrId {
    return generate("usr") as UsrId;
  }

  private static tupleKey(t: Tuple): string {
    return `${t.subjectType}|${t.subjectId}|${t.relation}|${t.objectType}|${t.objectId}`;
  }

  private static membershipTuple(m: Membership): Tuple {
    return {
      subjectType: "usr",
      subjectId: m.usrId,
      relation: m.role,
      objectType: "org",
      objectId: m.orgId,
    };
  }

  private insertTuple(t: Tuple): Tuple {
    this.tupleKeys.add(InMemoryTenancyStore.tupleKey(t));
    return t;
  }

  private deleteTuple(t: Tuple): void {
    this.tupleKeys.delete(InMemoryTenancyStore.tupleKey(t));
  }

  private countActiveOwners(orgId: OrgId): number {
    let n = 0;
    for (const m of this.memberships.values()) {
      if (m.orgId === orgId && m.status === "active" && m.role === "owner") n++;
    }
    return n;
  }

  private findActiveMembership(
    usrId: UsrId,
    orgId: OrgId,
  ): Membership | undefined {
    for (const m of this.memberships.values()) {
      if (m.usrId === usrId && m.orgId === orgId && m.status === "active") {
        return m;
      }
    }
    return undefined;
  }

  private requireOrg(orgId: OrgId): Organization {
    const o = this.orgs.get(orgId);
    if (!o) throw new NotFoundError(`Organization ${orgId} not found`);
    return o;
  }

  private requireMembership(memId: MemId): Membership {
    const m = this.memberships.get(memId);
    if (!m) throw new NotFoundError(`Membership ${memId} not found`);
    return m;
  }

  // ─── Organizations ───

  async createOrg(input: UsrId | CreateOrgInput): Promise<{
    org: Organization;
    ownerMembership: Membership;
  }> {
    // Backwards-compatible shim: accept either a bare creator UsrId
    // (v0.1 form) or a {creator, name?, slug?} object (v0.2 form).
    const normalized: CreateOrgInput =
      typeof input === "string" ? { creator: input } : input;
    if (normalized.slug !== undefined && normalized.slug !== null) {
      validateSlug(normalized.slug);
      this.enforceSlugUnique(normalized.slug, null);
    }
    const now = this.now();
    const org: Organization = {
      id: this.newOrgId(),
      status: "active",
      createdAt: now,
      updatedAt: now,
      name: normalized.name ?? null,
      slug: normalized.slug ?? null,
    };
    const ownerMembership: Membership = {
      id: this.newMemId(),
      usrId: normalized.creator,
      orgId: org.id,
      role: "owner",
      status: "active",
      replaces: null,
      invitedBy: null,
      removedBy: null,
      createdAt: now,
      updatedAt: now,
    };
    this.orgs.set(org.id, org);
    this.memberships.set(ownerMembership.id, ownerMembership);
    this.insertTuple(InMemoryTenancyStore.membershipTuple(ownerMembership));
    return { org, ownerMembership };
  }

  async getOrg(orgId: OrgId): Promise<Organization> {
    return this.requireOrg(orgId);
  }

  async updateOrg(input: UpdateOrgInput): Promise<Organization> {
    const org = await this.requireOrg(input.orgId);
    if (org.status === "revoked") {
      throw new AlreadyTerminalError(`Org ${input.orgId} is revoked; cannot update`);
    }
    const newName = "name" in input ? input.name ?? null : org.name ?? null;
    let newSlug = org.slug ?? null;
    if ("slug" in input) {
      if (input.slug !== null && input.slug !== undefined) {
        validateSlug(input.slug);
        this.enforceSlugUnique(input.slug, input.orgId);
      }
      newSlug = input.slug ?? null;
    }
    const updated: Organization = {
      ...org,
      name: newName,
      slug: newSlug,
      updatedAt: this.now(),
    };
    this.orgs.set(input.orgId, updated);
    return updated;
  }

  private enforceSlugUnique(slug: string, excludeOrgId: OrgId | null): void {
    for (const existing of this.orgs.values()) {
      if (existing.id === excludeOrgId) continue;
      if (existing.slug === slug && existing.status !== "revoked") {
        throw new OrgSlugConflictError(slug);
      }
    }
  }

  private transitionOrg(orgId: OrgId, to: Status): Organization {
    const org = this.requireOrg(orgId);
    if (org.status === to) {
      throw new AlreadyTerminalError(`Org ${orgId} is already ${to}`);
    }
    if (org.status === "revoked") {
      throw new AlreadyTerminalError(`Org ${orgId} is revoked; cannot transition`);
    }
    const updated: Organization = { ...org, status: to, updatedAt: this.now() };
    this.orgs.set(orgId, updated);
    return updated;
  }

  async suspendOrg(orgId: OrgId): Promise<Organization> {
    return this.transitionOrg(orgId, "suspended");
  }

  async reinstateOrg(orgId: OrgId): Promise<Organization> {
    const org = this.requireOrg(orgId);
    if (org.status !== "suspended") {
      throw new PreconditionError(
        `Org ${orgId} is ${org.status}; only suspended orgs can be reinstated`,
        "invalid_transition",
      );
    }
    return this.transitionOrg(orgId, "active");
  }

  async revokeOrg(orgId: OrgId): Promise<Organization> {
    const org = this.requireOrg(orgId);
    if (org.status === "revoked") {
      throw new AlreadyTerminalError(`Org ${orgId} is already revoked`);
    }
    // Cascade: revoke all active memberships, drop all org-scoped tuples.
    const now = this.now();
    for (const m of this.memberships.values()) {
      if (m.orgId === orgId && m.status === "active") {
        this.deleteTuple(InMemoryTenancyStore.membershipTuple(m));
        this.memberships.set(m.id, {
          ...m,
          status: "revoked",
          updatedAt: now,
        });
      }
    }
    const updated: Organization = { ...org, status: "revoked", updatedAt: now };
    this.orgs.set(orgId, updated);
    return updated;
  }

  // ─── Memberships ───

  async addMember(input: AddMemberInput): Promise<Membership> {
    const org = this.requireOrg(input.orgId);
    if (org.status !== "active") {
      throw new PreconditionError(
        `Cannot add member to ${org.status} org`,
        "org_not_active",
      );
    }
    if (this.findActiveMembership(input.usrId, input.orgId)) {
      throw new DuplicateMembershipError(
        `User ${input.usrId} already has an active membership in ${input.orgId}`,
      );
    }
    const now = this.now();
    const mem: Membership = {
      id: this.newMemId(),
      usrId: input.usrId,
      orgId: input.orgId,
      role: input.role,
      status: "active",
      replaces: null,
      invitedBy: input.invitedBy ?? null,
      removedBy: null,
      createdAt: now,
      updatedAt: now,
    };
    this.memberships.set(mem.id, mem);
    this.insertTuple(InMemoryTenancyStore.membershipTuple(mem));
    return mem;
  }

  async getMembership(memId: MemId): Promise<Membership> {
    return this.requireMembership(memId);
  }

  async listMembers(
    orgId: OrgId,
    options: ListMembersOptions = {},
  ): Promise<Page<Membership>> {
    const all = [...this.memberships.values()]
      .filter((m) => m.orgId === orgId)
      .filter((m) => (options.status ? m.status === options.status : true))
      .sort((a, b) => a.id.localeCompare(b.id));
    return this.paginate(all, options);
  }

  private paginate<T extends { id: string }>(
    all: T[],
    options: { cursor?: string; limit?: number } = {},
  ): Page<T> {
    const limit = options.limit ?? 50;
    const startIndex = options.cursor
      ? all.findIndex((x) => x.id > options.cursor!)
      : 0;
    const start = startIndex < 0 ? all.length : startIndex;
    const data = all.slice(start, start + limit);
    const nextCursor =
      start + limit < all.length ? (data[data.length - 1]?.id ?? null) : null;
    return { data, nextCursor };
  }

  async changeRole(input: ChangeRoleInput): Promise<Membership> {
    const old = this.requireMembership(input.memId);
    if (old.status !== "active") {
      throw new PreconditionError(
        `Membership ${input.memId} is ${old.status}; only active memberships can change role`,
        "mem_not_active",
      );
    }
    // Sole-owner protection: demoting the last active owner is forbidden.
    if (
      old.role === "owner" &&
      input.newRole !== "owner" &&
      this.countActiveOwners(old.orgId) === 1
    ) {
      throw new SoleOwnerError(
        `Cannot change role of the sole active owner; transfer ownership first`,
      );
    }
    const now = this.now();
    // Revoke old, insert new with replaces chain.
    const revoked: Membership = {
      ...old,
      status: "revoked",
      updatedAt: now,
      // NOTE: role-change is NOT an admin-removal; removedBy stays null to
      // distinguish it from adminRemove in audit queries. Audit reconstruction
      // uses the replaces chain (old.id → new.id) to identify role changes.
      removedBy: null,
    };
    this.memberships.set(old.id, revoked);
    this.deleteTuple(InMemoryTenancyStore.membershipTuple(old));
    const fresh: Membership = {
      id: this.newMemId(),
      usrId: old.usrId,
      orgId: old.orgId,
      role: input.newRole,
      status: "active",
      replaces: old.id,
      invitedBy: old.invitedBy,
      removedBy: null,
      createdAt: now,
      updatedAt: now,
    };
    this.memberships.set(fresh.id, fresh);
    this.insertTuple(InMemoryTenancyStore.membershipTuple(fresh));
    return fresh;
  }

  async suspendMembership(memId: MemId): Promise<Membership> {
    const mem = this.requireMembership(memId);
    if (mem.status !== "active") {
      throw new PreconditionError(
        `Membership ${memId} is ${mem.status}; only active memberships can be suspended`,
        "mem_not_active",
      );
    }
    if (mem.role === "owner" && this.countActiveOwners(mem.orgId) === 1) {
      throw new SoleOwnerError(
        `Cannot suspend the sole active owner; transfer ownership first`,
      );
    }
    const now = this.now();
    const updated: Membership = { ...mem, status: "suspended", updatedAt: now };
    this.memberships.set(memId, updated);
    this.deleteTuple(InMemoryTenancyStore.membershipTuple(mem));
    return updated;
  }

  async reinstateMembership(memId: MemId): Promise<Membership> {
    const mem = this.requireMembership(memId);
    if (mem.status !== "suspended") {
      throw new PreconditionError(
        `Membership ${memId} is ${mem.status}; only suspended memberships can be reinstated`,
        "invalid_transition",
      );
    }
    // Re-activation requires no active mem for the same (usr, org) pair.
    if (this.findActiveMembership(mem.usrId, mem.orgId)) {
      throw new DuplicateMembershipError(
        `User ${mem.usrId} has a separate active membership in ${mem.orgId}; cannot reinstate`,
      );
    }
    const now = this.now();
    const updated: Membership = { ...mem, status: "active", updatedAt: now };
    this.memberships.set(memId, updated);
    this.insertTuple(InMemoryTenancyStore.membershipTuple(updated));
    return updated;
  }

  async selfLeave(input: SelfLeaveInput): Promise<Membership> {
    const mem = this.requireMembership(input.memId);
    if (mem.status !== "active") {
      throw new PreconditionError(
        `Membership ${input.memId} is ${mem.status}; only active memberships can self-leave`,
        "mem_not_active",
      );
    }
    // Sole-owner protection: must atomically transfer ownership first.
    if (mem.role === "owner" && this.countActiveOwners(mem.orgId) === 1) {
      if (!input.transferTo) {
        throw new SoleOwnerError(
          `Cannot self-leave as sole active owner; pass transferTo to atomically transfer ownership`,
        );
      }
      const target = this.findActiveMembership(input.transferTo, mem.orgId);
      if (!target) {
        throw new NotFoundError(
          `transferTo user ${input.transferTo} has no active membership in ${mem.orgId}`,
        );
      }
      // Promote target to owner first; this creates a second active owner so
      // the subsequent self-revoke no longer trips the sole-owner guard.
      await this.changeRole({ memId: target.id, newRole: "owner" });
    }
    const now = this.now();
    const revoked: Membership = {
      ...mem,
      status: "revoked",
      updatedAt: now,
      removedBy: null, // null distinguishes self-leave from admin-remove
    };
    this.memberships.set(mem.id, revoked);
    this.deleteTuple(InMemoryTenancyStore.membershipTuple(mem));
    return revoked;
  }

  async adminRemove(input: AdminRemoveInput): Promise<Membership> {
    const target = this.requireMembership(input.memId);
    if (target.status !== "active") {
      throw new PreconditionError(
        `Target membership ${input.memId} is ${target.status}`,
        "mem_not_active",
      );
    }
    const admin = this.findActiveMembership(input.adminUsrId, target.orgId);
    if (!admin) {
      throw new ForbiddenError(
        `User ${input.adminUsrId} has no active membership in ${target.orgId}`,
      );
    }
    if (admin.role !== "owner" && admin.role !== "admin") {
      throw new ForbiddenError(
        `Role ${admin.role} is not permitted to remove members`,
      );
    }
    const adminRank = ADMIN_RANK[admin.role];
    const targetRank = ADMIN_RANK[target.role];
    if (adminRank === undefined || targetRank === undefined) {
      throw new PreconditionError(
        `adminRemove operates only on owner/admin/member/guest roles`,
        "scope_mismatch",
      );
    }
    if (target.role === "owner") {
      throw new RoleHierarchyError(
        `Owner removal requires transferOwnership, not adminRemove`,
      );
    }
    if (adminRank < targetRank) {
      throw new RoleHierarchyError(
        `Role ${admin.role} cannot remove role ${target.role}`,
      );
    }
    const now = this.now();
    const revoked: Membership = {
      ...target,
      status: "revoked",
      updatedAt: now,
      removedBy: admin.usrId, // non-null distinguishes admin-remove
    };
    this.memberships.set(target.id, revoked);
    this.deleteTuple(InMemoryTenancyStore.membershipTuple(target));
    return revoked;
  }

  async transferOwnership(input: TransferOwnershipInput): Promise<{
    fromMembership: Membership;
    toMembership: Membership;
  }> {
    const from = this.requireMembership(input.fromMemId);
    const to = this.requireMembership(input.toMemId);
    if (from.status !== "active") {
      throw new PreconditionError(
        `From membership ${input.fromMemId} is ${from.status}`,
        "from_not_active",
      );
    }
    if (to.status !== "active") {
      throw new PreconditionError(
        `To membership ${input.toMemId} is ${to.status}`,
        "to_not_active",
      );
    }
    if (from.orgId !== input.orgId || to.orgId !== input.orgId) {
      throw new PreconditionError(
        `Both memberships must belong to ${input.orgId}`,
        "org_mismatch",
      );
    }
    if (from.role !== "owner") {
      throw new PreconditionError(
        `From membership must hold the owner role`,
        "from_not_owner",
      );
    }
    if (from.usrId === to.usrId) {
      throw new PreconditionError(
        `Cannot transfer ownership to self`,
        "self_transfer",
      );
    }
    // Promote recipient first so the donor is no longer the sole active owner,
    // which would otherwise trip the changeRole sole-owner guard on demotion.
    const toMembership = await this.changeRole({
      memId: to.id,
      newRole: "owner",
    });
    const fromMembership = await this.changeRole({
      memId: from.id,
      newRole: "member",
    });
    return { fromMembership, toMembership };
  }

  // ─── Invitations ───

  async createInvitation(input: CreateInvitationInput): Promise<Invitation> {
    const org = this.requireOrg(input.orgId);
    if (org.status !== "active") {
      throw new PreconditionError(
        `Cannot create invitation for ${org.status} org`,
        "org_not_active",
      );
    }
    const now = this.now();
    if (input.expiresAt.getTime() <= now.getTime()) {
      throw new PreconditionError(
        `expiresAt must be in the future`,
        "past_expiration",
      );
    }
    const inv: Invitation = {
      id: this.newInvId(),
      orgId: input.orgId,
      identifier: input.identifier,
      role: input.role,
      status: "pending",
      preTuples: [...(input.preTuples ?? [])],
      invitedBy: input.invitedBy,
      invitedUserId: null,
      createdAt: now,
      expiresAt: input.expiresAt,
      terminalAt: null,
      terminalBy: null,
    };
    this.invitations.set(inv.id, inv);
    return inv;
  }

  async getInvitation(invId: InvId): Promise<Invitation> {
    const inv = this.invitations.get(invId);
    if (!inv) throw new NotFoundError(`Invitation ${invId} not found`);
    return inv;
  }

  async listInvitations(
    orgId: OrgId,
    options: ListInvitationsOptions = {},
  ): Promise<Page<Invitation>> {
    const all = [...this.invitations.values()]
      .filter((i) => i.orgId === orgId)
      .filter((i) => (options.status ? i.status === options.status : true))
      .sort((a, b) => a.id.localeCompare(b.id));
    return this.paginate(all, options);
  }

  async acceptInvitation(
    input: AcceptInvitationInput,
  ): Promise<AcceptInvitationResult> {
    const inv = await this.getInvitation(input.invId);
    if (inv.status !== "pending") {
      throw new InvitationNotPendingError(
        `Invitation ${input.invId} is ${inv.status}, not pending`,
      );
    }
    const now = this.now();
    if (now.getTime() > inv.expiresAt.getTime()) {
      throw new InvitationExpiredError(
        `Invitation ${input.invId} expired at ${inv.expiresAt.toISOString()}`,
      );
    }
    // ADR 0009: existing-user accept MUST supply a matching identifier.
    if (input.asUsrId !== undefined && input.asUsrId !== null) {
      if (
        input.acceptingIdentifier === undefined ||
        input.acceptingIdentifier === null
      ) {
        throw new IdentifierBindingRequiredError();
      }
      if (input.acceptingIdentifier !== inv.identifier) {
        throw new IdentifierMismatchError(input.acceptingIdentifier, inv.identifier);
      }
    }
    const usrId = input.asUsrId ?? this.newUsrId();
    if (this.findActiveMembership(usrId, inv.orgId)) {
      throw new DuplicateMembershipError(
        `User ${usrId} already has an active membership in ${inv.orgId}`,
      );
    }
    // Membership creation + tuple materialization happen in one logical
    // transaction — the spec's atomicity requirement for acceptInvitation.
    const membership: Membership = {
      id: this.newMemId(),
      usrId,
      orgId: inv.orgId,
      role: inv.role,
      status: "active",
      replaces: null,
      invitedBy: inv.invitedBy,
      removedBy: null,
      createdAt: now,
      updatedAt: now,
    };
    this.memberships.set(membership.id, membership);
    this.insertTuple(InMemoryTenancyStore.membershipTuple(membership));

    const materializedTuples: Tuple[] = [];
    for (const pt of inv.preTuples) {
      const t = this.materializePreTuple(usrId, pt);
      materializedTuples.push(t);
    }

    const updatedInv: Invitation = {
      ...inv,
      status: "accepted",
      terminalAt: now,
      terminalBy: usrId,
      invitedUserId: usrId,
    };
    this.invitations.set(inv.id, updatedInv);

    return { invitation: updatedInv, membership, materializedTuples };
  }

  private materializePreTuple(usrId: UsrId, pt: PreTuple): Tuple {
    const t: Tuple = {
      subjectType: "usr",
      subjectId: usrId,
      relation: pt.relation,
      objectType: pt.objectType,
      objectId: pt.objectId,
    };
    this.insertTuple(t);
    return t;
  }

  async declineInvitation(input: DeclineInvitationInput): Promise<Invitation> {
    const inv = await this.getInvitation(input.invId);
    if (inv.status !== "pending") {
      throw new InvitationNotPendingError(
        `Invitation ${input.invId} is ${inv.status}, not pending`,
      );
    }
    const now = this.now();
    const updated: Invitation = {
      ...inv,
      status: "declined",
      terminalAt: now,
      terminalBy: input.asUsrId ?? null,
    };
    this.invitations.set(inv.id, updated);
    return updated;
  }

  async revokeInvitation(input: RevokeInvitationInput): Promise<Invitation> {
    const inv = await this.getInvitation(input.invId);
    if (inv.status !== "pending") {
      throw new InvitationNotPendingError(
        `Invitation ${input.invId} is ${inv.status}, not pending`,
      );
    }
    const now = this.now();
    const updated: Invitation = {
      ...inv,
      status: "revoked",
      terminalAt: now,
      terminalBy: input.adminUsrId,
    };
    this.invitations.set(inv.id, updated);
    return updated;
  }

  // ─── Tuple accessors ───

  async listTuplesForSubject(
    subjectType: "usr",
    subjectId: UsrId,
  ): Promise<Tuple[]> {
    const prefix = `${subjectType}|${subjectId}|`;
    const results: Tuple[] = [];
    for (const key of this.tupleKeys) {
      if (!key.startsWith(prefix)) continue;
      const parts = key.split("|");
      if (parts.length !== 5) continue;
      const [st, sid, relation, objectType, objectId] = parts as [
        string,
        string,
        string,
        string,
        string,
      ];
      if (st !== "usr") continue;
      results.push({
        subjectType: "usr",
        subjectId: sid as UsrId,
        relation,
        objectType,
        objectId,
      });
    }
    return results;
  }

  async listTuplesForObject(
    objectType: string,
    objectId: string,
    relation?: string,
  ): Promise<Tuple[]> {
    const results: Tuple[] = [];
    for (const key of this.tupleKeys) {
      const parts = key.split("|");
      if (parts.length !== 5) continue;
      const [st, sid, rel, ot, oid] = parts as [
        string,
        string,
        string,
        string,
        string,
      ];
      if (ot !== objectType || oid !== objectId) continue;
      if (relation !== undefined && rel !== relation) continue;
      if (st !== "usr") continue;
      results.push({
        subjectType: "usr",
        subjectId: sid as UsrId,
        relation: rel,
        objectType,
        objectId,
      });
    }
    return results;
  }
}

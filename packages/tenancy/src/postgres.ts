// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * PostgresTenancyStore — the production-ready backend for
 * @flametrench/tenancy.
 *
 * Lives in a separate entry point (`@flametrench/tenancy/postgres`) so the
 * base package stays Postgres-free. Applications that use the in-memory
 * store or a future alternative backend don't transitively pull pg.
 *
 * Usage:
 *
 *     import { Pool } from "pg";
 *     import { PostgresTenancyStore } from "@flametrench/tenancy/postgres";
 *
 *     const pool = new Pool({ connectionString: process.env.DATABASE_URL });
 *     const store = new PostgresTenancyStore(pool);
 *     const { org, ownerMembership } = await store.createOrg(aliceId);
 *
 * **Schema.** Apply `spec/reference/postgres.sql` (or its vendored copy
 * for this SDK at `packages/tenancy/test/postgres-schema.sql`) to the
 * target database before using this store.
 *
 * **Transactions.** Every operation that touches more than one row runs
 * inside a `BEGIN`/`COMMIT` block, so the spec's atomicity guarantees
 * (membership + tuple created together, invitation accept materializes
 * pre-tuples atomically, etc.) are backed by a real database transaction.
 * On any error the transaction rolls back and no partial state persists.
 *
 * **ID encoding.** IDs are stored as native `UUID` in Postgres per the
 * spec; the wire format (`org_0190...`) is computed at the API boundary
 * via @flametrench/ids. This store accepts wire-format IDs at its API
 * and converts to/from UUIDs internally.
 */

import { decode, encode, generate } from "@flametrench/ids";
import type { Pool, PoolClient } from "pg";

import {
  AlreadyTerminalError,
  DuplicateMembershipError,
  ForbiddenError,
  InvitationExpiredError,
  InvitationNotPendingError,
  NotFoundError,
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
  Role,
  SelfLeaveInput,
  Status,
  TransferOwnershipInput,
  Tuple,
  UsrId,
} from "./types.js";

const ADMIN_RANK: Record<string, number> = {
  owner: 4,
  admin: 3,
  member: 2,
  guest: 1,
};

// ─── ID conversion helpers ───

/** Strip the `type_` prefix and rehydrate canonical hyphenated UUID. */
function wireToUuid(wireId: string): string {
  return decode(wireId).uuid;
}

function orgIdOf(uuid: string): OrgId {
  return encode("org", uuid) as OrgId;
}
function memIdOf(uuid: string): MemId {
  return encode("mem", uuid) as MemId;
}
function invIdOf(uuid: string): InvId {
  return encode("inv", uuid) as InvId;
}
function usrIdOf(uuid: string): UsrId {
  return encode("usr", uuid) as UsrId;
}

// ─── Row types (match the reference DDL column names) ───

interface OrgRow {
  id: string;
  status: Status;
  created_at: Date;
  updated_at: Date;
}
interface MemRow {
  id: string;
  usr_id: string;
  org_id: string;
  role: Role;
  status: Status;
  replaces: string | null;
  invited_by: string | null;
  removed_by: string | null;
  created_at: Date;
  updated_at: Date;
}
interface InvRow {
  id: string;
  org_id: string;
  identifier: string;
  role: Role;
  status: Invitation["status"];
  pre_tuples: PreTuple[];
  invited_by: string;
  invited_user_id: string | null;
  created_at: Date;
  expires_at: Date;
  terminal_at: Date | null;
  terminal_by: string | null;
}
interface TupRow {
  id: string;
  subject_type: "usr";
  subject_id: string;
  relation: string;
  object_type: string;
  object_id: string;
  created_at: Date;
  created_by: string | null;
}

// ─── Row → entity mappers ───

function rowToOrg(r: OrgRow): Organization {
  return {
    id: orgIdOf(r.id),
    status: r.status,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}
function rowToMem(r: MemRow): Membership {
  return {
    id: memIdOf(r.id),
    usrId: usrIdOf(r.usr_id),
    orgId: orgIdOf(r.org_id),
    role: r.role,
    status: r.status,
    replaces: r.replaces ? memIdOf(r.replaces) : null,
    invitedBy: r.invited_by ? usrIdOf(r.invited_by) : null,
    removedBy: r.removed_by ? usrIdOf(r.removed_by) : null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}
function rowToInv(r: InvRow): Invitation {
  return {
    id: invIdOf(r.id),
    orgId: orgIdOf(r.org_id),
    identifier: r.identifier,
    role: r.role,
    status: r.status,
    preTuples: Array.isArray(r.pre_tuples)
      ? r.pre_tuples.map((pt: unknown) => {
          const o = pt as Record<string, unknown>;
          return {
            relation: String(o.relation ?? o["relation"]),
            objectType: String(o.object_type ?? o.objectType),
            objectId: String(o.object_id ?? o.objectId),
          };
        })
      : [],
    invitedBy: usrIdOf(r.invited_by),
    invitedUserId: r.invited_user_id ? usrIdOf(r.invited_user_id) : null,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    terminalAt: r.terminal_at,
    terminalBy: r.terminal_by ? usrIdOf(r.terminal_by) : null,
  };
}
function rowToTup(r: TupRow): Tuple {
  return {
    subjectType: r.subject_type,
    subjectId: usrIdOf(r.subject_id),
    relation: r.relation,
    objectType: r.object_type,
    objectId: r.object_id,
  };
}

// Convert a PreTuple (camelCase, app-facing) to the JSONB shape persisted
// in inv.pre_tuples (snake_case, matches the ref schema).
function preTupleToJson(pt: PreTuple): Record<string, string> {
  return {
    relation: pt.relation,
    object_type: pt.objectType,
    object_id: pt.objectId,
  };
}

// ─── Postgres error code → TenancyError mapping ───

function isPgError(e: unknown, code: string): boolean {
  return (
    typeof e === "object" &&
    e !== null &&
    "code" in e &&
    (e as { code: unknown }).code === code
  );
}

export interface PostgresTenancyStoreOptions {
  /** Override the clock. Default `() => new Date()`. */
  clock?: () => Date;
}

/**
 * Postgres-backed TenancyStore. See file-level docs for usage.
 */
export class PostgresTenancyStore implements TenancyStore {
  private readonly clock: () => Date;

  constructor(
    private readonly pool: Pool,
    options: PostgresTenancyStoreOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
  }

  private now(): Date {
    return this.clock();
  }

  // ─── Transaction helper ───

  private async tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // Rollback may fail if connection is broken; swallow so we surface the original error.
      }
      throw err;
    } finally {
      client.release();
    }
  }

  // ─── Organizations ───

  async createOrg(creator: UsrId): Promise<{
    org: Organization;
    ownerMembership: Membership;
  }> {
    const now = this.now();
    const orgUuid = decode(generate("org")).uuid;
    const memUuid = decode(generate("mem")).uuid;
    const tupUuid = decode(generate("tup")).uuid;
    const creatorUuid = wireToUuid(creator);

    return this.tx(async (c) => {
      await c.query(
        `INSERT INTO org (id, status, created_at, updated_at) VALUES ($1, 'active', $2, $2)`,
        [orgUuid, now],
      );
      await c.query(
        `INSERT INTO mem (id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at)
         VALUES ($1, $2, $3, 'owner', 'active', NULL, NULL, NULL, $4, $4)`,
        [memUuid, creatorUuid, orgUuid, now],
      );
      await c.query(
        `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
         VALUES ($1, 'usr', $2, 'owner', 'org', $3, $4, $2)`,
        [tupUuid, creatorUuid, orgUuid, now],
      );
      const org: Organization = {
        id: orgIdOf(orgUuid),
        status: "active",
        createdAt: now,
        updatedAt: now,
      };
      const ownerMembership: Membership = {
        id: memIdOf(memUuid),
        usrId: creator,
        orgId: org.id,
        role: "owner",
        status: "active",
        replaces: null,
        invitedBy: null,
        removedBy: null,
        createdAt: now,
        updatedAt: now,
      };
      return { org, ownerMembership };
    });
  }

  async getOrg(orgId: OrgId): Promise<Organization> {
    const { rows } = await this.pool.query<OrgRow>(
      `SELECT id, status, created_at, updated_at FROM org WHERE id = $1`,
      [wireToUuid(orgId)],
    );
    if (rows.length === 0) throw new NotFoundError(`Organization ${orgId} not found`);
    return rowToOrg(rows[0]!);
  }

  private async transitionOrg(orgId: OrgId, to: Status): Promise<Organization> {
    return this.tx(async (c) => {
      const { rows } = await c.query<OrgRow>(
        `SELECT id, status, created_at, updated_at FROM org WHERE id = $1 FOR UPDATE`,
        [wireToUuid(orgId)],
      );
      if (rows.length === 0) throw new NotFoundError(`Organization ${orgId} not found`);
      const row = rows[0]!;
      if (row.status === "revoked") {
        throw new AlreadyTerminalError(`Org ${orgId} is revoked; cannot transition`);
      }
      if (row.status === to) {
        throw new AlreadyTerminalError(`Org ${orgId} is already ${to}`);
      }
      const now = this.now();
      const { rows: updated } = await c.query<OrgRow>(
        `UPDATE org SET status = $1, updated_at = $2 WHERE id = $3
         RETURNING id, status, created_at, updated_at`,
        [to, now, wireToUuid(orgId)],
      );
      return rowToOrg(updated[0]!);
    });
  }

  async suspendOrg(orgId: OrgId): Promise<Organization> {
    return this.transitionOrg(orgId, "suspended");
  }

  async reinstateOrg(orgId: OrgId): Promise<Organization> {
    return this.tx(async (c) => {
      const { rows } = await c.query<OrgRow>(
        `SELECT id, status, created_at, updated_at FROM org WHERE id = $1 FOR UPDATE`,
        [wireToUuid(orgId)],
      );
      if (rows.length === 0) throw new NotFoundError(`Organization ${orgId} not found`);
      if (rows[0]!.status !== "suspended") {
        throw new PreconditionError(
          `Org ${orgId} is ${rows[0]!.status}; only suspended orgs can be reinstated`,
          "invalid_transition",
        );
      }
      const now = this.now();
      const { rows: updated } = await c.query<OrgRow>(
        `UPDATE org SET status = 'active', updated_at = $1 WHERE id = $2
         RETURNING id, status, created_at, updated_at`,
        [now, wireToUuid(orgId)],
      );
      return rowToOrg(updated[0]!);
    });
  }

  async revokeOrg(orgId: OrgId): Promise<Organization> {
    return this.tx(async (c) => {
      const { rows } = await c.query<OrgRow>(
        `SELECT id, status, created_at, updated_at FROM org WHERE id = $1 FOR UPDATE`,
        [wireToUuid(orgId)],
      );
      if (rows.length === 0) throw new NotFoundError(`Organization ${orgId} not found`);
      if (rows[0]!.status === "revoked") {
        throw new AlreadyTerminalError(`Org ${orgId} is already revoked`);
      }
      const now = this.now();
      const orgUuid = wireToUuid(orgId);
      // Cascade: delete tuples and revoke active memberships.
      await c.query(
        `DELETE FROM tup WHERE object_type = 'org' AND object_id = $1`,
        [orgUuid],
      );
      await c.query(
        `UPDATE mem SET status = 'revoked', updated_at = $1
         WHERE org_id = $2 AND status = 'active'`,
        [now, orgUuid],
      );
      const { rows: updated } = await c.query<OrgRow>(
        `UPDATE org SET status = 'revoked', updated_at = $1 WHERE id = $2
         RETURNING id, status, created_at, updated_at`,
        [now, orgUuid],
      );
      return rowToOrg(updated[0]!);
    });
  }

  // ─── Memberships ───

  async addMember(input: AddMemberInput): Promise<Membership> {
    return this.tx(async (c) => {
      const orgRow = await c.query<OrgRow>(
        `SELECT status FROM org WHERE id = $1`,
        [wireToUuid(input.orgId)],
      );
      if (orgRow.rows.length === 0) {
        throw new NotFoundError(`Organization ${input.orgId} not found`);
      }
      if (orgRow.rows[0]!.status !== "active") {
        throw new PreconditionError(
          `Cannot add member to ${orgRow.rows[0]!.status} org`,
          "org_not_active",
        );
      }
      const memUuid = decode(generate("mem")).uuid;
      const tupUuid = decode(generate("tup")).uuid;
      const now = this.now();
      const usrUuid = wireToUuid(input.usrId);
      const orgUuid = wireToUuid(input.orgId);
      const invitedByUuid = input.invitedBy ? wireToUuid(input.invitedBy) : null;
      try {
        const { rows } = await c.query<MemRow>(
          `INSERT INTO mem (id, usr_id, org_id, role, status, invited_by, created_at, updated_at)
           VALUES ($1, $2, $3, $4, 'active', $5, $6, $6)
           RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
          [memUuid, usrUuid, orgUuid, input.role, invitedByUuid, now],
        );
        await c.query(
          `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
           VALUES ($1, 'usr', $2, $3, 'org', $4, $5, $6)`,
          [tupUuid, usrUuid, input.role, orgUuid, now, invitedByUuid],
        );
        return rowToMem(rows[0]!);
      } catch (e) {
        if (isPgError(e, "23505")) {
          // unique_violation — the mem_unique_active partial index fired.
          throw new DuplicateMembershipError(
            `User ${input.usrId} already has an active membership in ${input.orgId}`,
          );
        }
        throw e;
      }
    });
  }

  async getMembership(memId: MemId): Promise<Membership> {
    const { rows } = await this.pool.query<MemRow>(
      `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at
       FROM mem WHERE id = $1`,
      [wireToUuid(memId)],
    );
    if (rows.length === 0) throw new NotFoundError(`Membership ${memId} not found`);
    return rowToMem(rows[0]!);
  }

  async listMembers(
    orgId: OrgId,
    options: ListMembersOptions = {},
  ): Promise<Page<Membership>> {
    const limit = options.limit ?? 50;
    const params: unknown[] = [wireToUuid(orgId)];
    const conditions = ["org_id = $1"];
    if (options.status) {
      params.push(options.status);
      conditions.push(`status = $${params.length}`);
    }
    if (options.cursor) {
      params.push(wireToUuid(options.cursor));
      conditions.push(`id > $${params.length}`);
    }
    params.push(limit);
    const { rows } = await this.pool.query<MemRow>(
      `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at
       FROM mem
       WHERE ${conditions.join(" AND ")}
       ORDER BY id
       LIMIT $${params.length}`,
      params,
    );
    const data = rows.map(rowToMem);
    const nextCursor =
      data.length === limit ? (data[data.length - 1]?.id ?? null) : null;
    return { data, nextCursor };
  }

  async changeRole(input: ChangeRoleInput): Promise<Membership> {
    return this.tx(async (c) => {
      const memUuid = wireToUuid(input.memId);
      const oldRes = await c.query<MemRow>(
        `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at
         FROM mem WHERE id = $1 FOR UPDATE`,
        [memUuid],
      );
      if (oldRes.rows.length === 0) {
        throw new NotFoundError(`Membership ${input.memId} not found`);
      }
      const old = oldRes.rows[0]!;
      if (old.status !== "active") {
        throw new PreconditionError(
          `Membership ${input.memId} is ${old.status}; only active memberships can change role`,
          "mem_not_active",
        );
      }
      if (old.role === "owner" && input.newRole !== "owner") {
        const owners = await c.query<{ count: string }>(
          `SELECT COUNT(*)::text AS count FROM mem WHERE org_id = $1 AND role = 'owner' AND status = 'active'`,
          [old.org_id],
        );
        if (Number(owners.rows[0]!.count) === 1) {
          throw new SoleOwnerError(
            `Cannot change role of the sole active owner; transfer ownership first`,
          );
        }
      }
      const now = this.now();
      const newMemUuid = decode(generate("mem")).uuid;
      const newTupUuid = decode(generate("tup")).uuid;
      await c.query(
        `UPDATE mem SET status = 'revoked', updated_at = $1 WHERE id = $2`,
        [now, old.id],
      );
      await c.query(
        `DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
        [old.usr_id, old.role, old.org_id],
      );
      const { rows: inserted } = await c.query<MemRow>(
        `INSERT INTO mem (id, usr_id, org_id, role, status, replaces, invited_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $7)
         RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
        [newMemUuid, old.usr_id, old.org_id, input.newRole, old.id, old.invited_by, now],
      );
      await c.query(
        `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
         VALUES ($1, 'usr', $2, $3, 'org', $4, $5)`,
        [newTupUuid, old.usr_id, input.newRole, old.org_id, now],
      );
      return rowToMem(inserted[0]!);
    });
  }

  async suspendMembership(memId: MemId): Promise<Membership> {
    return this.tx(async (c) => {
      const res = await c.query<MemRow>(
        `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at
         FROM mem WHERE id = $1 FOR UPDATE`,
        [wireToUuid(memId)],
      );
      if (res.rows.length === 0) throw new NotFoundError(`Membership ${memId} not found`);
      const mem = res.rows[0]!;
      if (mem.status !== "active") {
        throw new PreconditionError(
          `Membership ${memId} is ${mem.status}`,
          "mem_not_active",
        );
      }
      if (mem.role === "owner") {
        const owners = await c.query<{ count: string }>(
          `SELECT COUNT(*)::text AS count FROM mem WHERE org_id = $1 AND role = 'owner' AND status = 'active'`,
          [mem.org_id],
        );
        if (Number(owners.rows[0]!.count) === 1) {
          throw new SoleOwnerError(
            `Cannot suspend the sole active owner; transfer ownership first`,
          );
        }
      }
      const now = this.now();
      await c.query(
        `DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
        [mem.usr_id, mem.role, mem.org_id],
      );
      const { rows } = await c.query<MemRow>(
        `UPDATE mem SET status = 'suspended', updated_at = $1 WHERE id = $2
         RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
        [now, mem.id],
      );
      return rowToMem(rows[0]!);
    });
  }

  async reinstateMembership(memId: MemId): Promise<Membership> {
    return this.tx(async (c) => {
      const res = await c.query<MemRow>(
        `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at
         FROM mem WHERE id = $1 FOR UPDATE`,
        [wireToUuid(memId)],
      );
      if (res.rows.length === 0) throw new NotFoundError(`Membership ${memId} not found`);
      const mem = res.rows[0]!;
      if (mem.status !== "suspended") {
        throw new PreconditionError(
          `Membership ${memId} is ${mem.status}; only suspended memberships can be reinstated`,
          "invalid_transition",
        );
      }
      // Require no other active mem for this (usr, org).
      const active = await c.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM mem WHERE usr_id = $1 AND org_id = $2 AND status = 'active'`,
        [mem.usr_id, mem.org_id],
      );
      if (Number(active.rows[0]!.count) > 0) {
        throw new DuplicateMembershipError(
          `User has a separate active membership in this org; cannot reinstate`,
        );
      }
      const now = this.now();
      const newTupUuid = decode(generate("tup")).uuid;
      const { rows } = await c.query<MemRow>(
        `UPDATE mem SET status = 'active', updated_at = $1 WHERE id = $2
         RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
        [now, mem.id],
      );
      await c.query(
        `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
         VALUES ($1, 'usr', $2, $3, 'org', $4, $5)`,
        [newTupUuid, mem.usr_id, mem.role, mem.org_id, now],
      );
      return rowToMem(rows[0]!);
    });
  }

  async selfLeave(input: SelfLeaveInput): Promise<Membership> {
    return this.tx(async (c) => {
      const res = await c.query<MemRow>(
        `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at
         FROM mem WHERE id = $1 FOR UPDATE`,
        [wireToUuid(input.memId)],
      );
      if (res.rows.length === 0) throw new NotFoundError(`Membership ${input.memId} not found`);
      const mem = res.rows[0]!;
      if (mem.status !== "active") {
        throw new PreconditionError(
          `Membership ${input.memId} is ${mem.status}`,
          "mem_not_active",
        );
      }
      if (mem.role === "owner") {
        const owners = await c.query<{ count: string }>(
          `SELECT COUNT(*)::text AS count FROM mem WHERE org_id = $1 AND role = 'owner' AND status = 'active'`,
          [mem.org_id],
        );
        if (Number(owners.rows[0]!.count) === 1) {
          if (!input.transferTo) {
            throw new SoleOwnerError(
              `Cannot self-leave as sole active owner; pass transferTo to atomically transfer ownership`,
            );
          }
          const targetUuid = wireToUuid(input.transferTo);
          const targetRes = await c.query<MemRow>(
            `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at
             FROM mem WHERE usr_id = $1 AND org_id = $2 AND status = 'active' FOR UPDATE`,
            [targetUuid, mem.org_id],
          );
          if (targetRes.rows.length === 0) {
            throw new NotFoundError(
              `transferTo user ${input.transferTo} has no active membership in org`,
            );
          }
          // Promote target to owner (in-transaction, reuses this transaction's connection).
          const target = targetRes.rows[0]!;
          const newMemUuid = decode(generate("mem")).uuid;
          const newTupUuid = decode(generate("tup")).uuid;
          const now2 = this.now();
          await c.query(
            `UPDATE mem SET status = 'revoked', updated_at = $1 WHERE id = $2`,
            [now2, target.id],
          );
          await c.query(
            `DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
            [target.usr_id, target.role, target.org_id],
          );
          await c.query(
            `INSERT INTO mem (id, usr_id, org_id, role, status, replaces, invited_by, created_at, updated_at)
             VALUES ($1, $2, $3, 'owner', 'active', $4, $5, $6, $6)`,
            [newMemUuid, target.usr_id, target.org_id, target.id, target.invited_by, now2],
          );
          await c.query(
            `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
             VALUES ($1, 'usr', $2, 'owner', 'org', $3, $4)`,
            [newTupUuid, target.usr_id, target.org_id, now2],
          );
        }
      }
      const now = this.now();
      await c.query(
        `DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
        [mem.usr_id, mem.role, mem.org_id],
      );
      const { rows } = await c.query<MemRow>(
        `UPDATE mem SET status = 'revoked', removed_by = NULL, updated_at = $1 WHERE id = $2
         RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
        [now, mem.id],
      );
      return rowToMem(rows[0]!);
    });
  }

  async adminRemove(input: AdminRemoveInput): Promise<Membership> {
    return this.tx(async (c) => {
      const targetRes = await c.query<MemRow>(
        `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at
         FROM mem WHERE id = $1 FOR UPDATE`,
        [wireToUuid(input.memId)],
      );
      if (targetRes.rows.length === 0) throw new NotFoundError(`Membership ${input.memId} not found`);
      const target = targetRes.rows[0]!;
      if (target.status !== "active") {
        throw new PreconditionError(
          `Target membership is ${target.status}`,
          "mem_not_active",
        );
      }
      const adminRes = await c.query<MemRow>(
        `SELECT id, usr_id, org_id, role, status FROM mem
         WHERE usr_id = $1 AND org_id = $2 AND status = 'active'`,
        [wireToUuid(input.adminUsrId), target.org_id],
      );
      if (adminRes.rows.length === 0) {
        throw new ForbiddenError(
          `Admin user has no active membership in ${orgIdOf(target.org_id)}`,
        );
      }
      const admin = adminRes.rows[0]!;
      if (admin.role !== "owner" && admin.role !== "admin") {
        throw new ForbiddenError(
          `Role ${admin.role} is not permitted to remove members`,
        );
      }
      if (target.role === "owner") {
        throw new RoleHierarchyError(
          `Owner removal requires transferOwnership, not adminRemove`,
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
      if (adminRank < targetRank) {
        throw new RoleHierarchyError(
          `Role ${admin.role} cannot remove role ${target.role}`,
        );
      }
      const now = this.now();
      await c.query(
        `DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
        [target.usr_id, target.role, target.org_id],
      );
      const { rows } = await c.query<MemRow>(
        `UPDATE mem SET status = 'revoked', removed_by = $1, updated_at = $2 WHERE id = $3
         RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
        [admin.usr_id, now, target.id],
      );
      return rowToMem(rows[0]!);
    });
  }

  async transferOwnership(input: TransferOwnershipInput): Promise<{
    fromMembership: Membership;
    toMembership: Membership;
  }> {
    return this.tx(async (c) => {
      const orgUuid = wireToUuid(input.orgId);
      const fromUuid = wireToUuid(input.fromMemId);
      const toUuid = wireToUuid(input.toMemId);

      const [fromRes, toRes] = await Promise.all([
        c.query<MemRow>(
          `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at FROM mem WHERE id = $1 FOR UPDATE`,
          [fromUuid],
        ),
        c.query<MemRow>(
          `SELECT id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at FROM mem WHERE id = $1 FOR UPDATE`,
          [toUuid],
        ),
      ]);
      if (fromRes.rows.length === 0) throw new NotFoundError(`From membership ${input.fromMemId} not found`);
      if (toRes.rows.length === 0) throw new NotFoundError(`To membership ${input.toMemId} not found`);
      const from = fromRes.rows[0]!;
      const to = toRes.rows[0]!;
      if (from.status !== "active") {
        throw new PreconditionError(`From membership is ${from.status}`, "from_not_active");
      }
      if (to.status !== "active") {
        throw new PreconditionError(`To membership is ${to.status}`, "to_not_active");
      }
      if (from.org_id !== orgUuid || to.org_id !== orgUuid) {
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
      if (from.usr_id === to.usr_id) {
        throw new PreconditionError(
          `Cannot transfer ownership to self`,
          "self_transfer",
        );
      }
      const now = this.now();
      // Promote `to` to owner first.
      const toNewMemUuid = decode(generate("mem")).uuid;
      const toNewTupUuid = decode(generate("tup")).uuid;
      await c.query(`UPDATE mem SET status = 'revoked', updated_at = $1 WHERE id = $2`, [now, to.id]);
      await c.query(
        `DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
        [to.usr_id, to.role, to.org_id],
      );
      const { rows: toRows } = await c.query<MemRow>(
        `INSERT INTO mem (id, usr_id, org_id, role, status, replaces, invited_by, created_at, updated_at)
         VALUES ($1, $2, $3, 'owner', 'active', $4, $5, $6, $6)
         RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
        [toNewMemUuid, to.usr_id, to.org_id, to.id, to.invited_by, now],
      );
      await c.query(
        `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
         VALUES ($1, 'usr', $2, 'owner', 'org', $3, $4)`,
        [toNewTupUuid, to.usr_id, to.org_id, now],
      );
      // Then demote `from` to member.
      const fromNewMemUuid = decode(generate("mem")).uuid;
      const fromNewTupUuid = decode(generate("tup")).uuid;
      await c.query(`UPDATE mem SET status = 'revoked', updated_at = $1 WHERE id = $2`, [now, from.id]);
      await c.query(
        `DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = 'owner' AND object_type = 'org' AND object_id = $2`,
        [from.usr_id, from.org_id],
      );
      const { rows: fromRows } = await c.query<MemRow>(
        `INSERT INTO mem (id, usr_id, org_id, role, status, replaces, invited_by, created_at, updated_at)
         VALUES ($1, $2, $3, 'member', 'active', $4, $5, $6, $6)
         RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
        [fromNewMemUuid, from.usr_id, from.org_id, from.id, from.invited_by, now],
      );
      await c.query(
        `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
         VALUES ($1, 'usr', $2, 'member', 'org', $3, $4)`,
        [fromNewTupUuid, from.usr_id, from.org_id, now],
      );
      return {
        fromMembership: rowToMem(fromRows[0]!),
        toMembership: rowToMem(toRows[0]!),
      };
    });
  }

  // ─── Invitations ───

  async createInvitation(input: CreateInvitationInput): Promise<Invitation> {
    const org = await this.getOrg(input.orgId);
    if (org.status !== "active") {
      throw new PreconditionError(
        `Cannot create invitation for ${org.status} org`,
        "org_not_active",
      );
    }
    const now = this.now();
    if (input.expiresAt.getTime() <= now.getTime()) {
      throw new PreconditionError(`expiresAt must be in the future`, "past_expiration");
    }
    const invUuid = decode(generate("inv")).uuid;
    const preTuplesJson = (input.preTuples ?? []).map(preTupleToJson);
    const { rows } = await this.pool.query<InvRow>(
      `INSERT INTO inv (id, org_id, identifier, role, status, pre_tuples, invited_by, created_at, expires_at)
       VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8)
       RETURNING id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by`,
      [
        invUuid,
        wireToUuid(input.orgId),
        input.identifier,
        input.role,
        JSON.stringify(preTuplesJson),
        wireToUuid(input.invitedBy),
        now,
        input.expiresAt,
      ],
    );
    return rowToInv(rows[0]!);
  }

  async getInvitation(invId: InvId): Promise<Invitation> {
    const { rows } = await this.pool.query<InvRow>(
      `SELECT id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by
       FROM inv WHERE id = $1`,
      [wireToUuid(invId)],
    );
    if (rows.length === 0) throw new NotFoundError(`Invitation ${invId} not found`);
    return rowToInv(rows[0]!);
  }

  async listInvitations(
    orgId: OrgId,
    options: ListInvitationsOptions = {},
  ): Promise<Page<Invitation>> {
    const limit = options.limit ?? 50;
    const params: unknown[] = [wireToUuid(orgId)];
    const conditions = ["org_id = $1"];
    if (options.status) {
      params.push(options.status);
      conditions.push(`status = $${params.length}`);
    }
    if (options.cursor) {
      params.push(wireToUuid(options.cursor));
      conditions.push(`id > $${params.length}`);
    }
    params.push(limit);
    const { rows } = await this.pool.query<InvRow>(
      `SELECT id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by
       FROM inv
       WHERE ${conditions.join(" AND ")}
       ORDER BY id
       LIMIT $${params.length}`,
      params,
    );
    const data = rows.map(rowToInv);
    const nextCursor =
      data.length === limit ? (data[data.length - 1]?.id ?? null) : null;
    return { data, nextCursor };
  }

  async acceptInvitation(input: AcceptInvitationInput): Promise<AcceptInvitationResult> {
    return this.tx(async (c) => {
      const invRes = await c.query<InvRow>(
        `SELECT id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by
         FROM inv WHERE id = $1 FOR UPDATE`,
        [wireToUuid(input.invId)],
      );
      if (invRes.rows.length === 0) throw new NotFoundError(`Invitation ${input.invId} not found`);
      const inv = invRes.rows[0]!;
      if (inv.status !== "pending") {
        throw new InvitationNotPendingError(
          `Invitation ${input.invId} is ${inv.status}, not pending`,
        );
      }
      const now = this.now();
      if (now.getTime() > inv.expires_at.getTime()) {
        throw new InvitationExpiredError(
          `Invitation ${input.invId} expired at ${inv.expires_at.toISOString()}`,
        );
      }
      const usrUuid = input.asUsrId ? wireToUuid(input.asUsrId) : decode(generate("usr")).uuid;
      // Duplicate-membership check (partial index would also catch this; check explicitly for clean error).
      const dup = await c.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM mem WHERE usr_id = $1 AND org_id = $2 AND status = 'active'`,
        [usrUuid, inv.org_id],
      );
      if (Number(dup.rows[0]!.count) > 0) {
        throw new DuplicateMembershipError(
          `User ${usrIdOf(usrUuid)} already has an active membership in ${orgIdOf(inv.org_id)}`,
        );
      }
      const memUuid = decode(generate("mem")).uuid;
      const memTupUuid = decode(generate("tup")).uuid;
      const { rows: memRows } = await c.query<MemRow>(
        `INSERT INTO mem (id, usr_id, org_id, role, status, invited_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'active', $5, $6, $6)
         RETURNING id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`,
        [memUuid, usrUuid, inv.org_id, inv.role, inv.invited_by, now],
      );
      await c.query(
        `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
         VALUES ($1, 'usr', $2, $3, 'org', $4, $5)`,
        [memTupUuid, usrUuid, inv.role, inv.org_id, now],
      );

      const materializedTuples: Tuple[] = [];
      const preTuples: unknown[] = Array.isArray(inv.pre_tuples) ? inv.pre_tuples : [];
      for (const pt of preTuples) {
        const obj = pt as Record<string, unknown>;
        const relation = String(obj.relation ?? obj["relation"]);
        const objectType = String(obj.object_type ?? obj.objectType);
        const objectId = String(obj.object_id ?? obj.objectId);
        const ptTupUuid = decode(generate("tup")).uuid;
        await c.query(
          `INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at)
           VALUES ($1, 'usr', $2, $3, $4, $5, $6)`,
          [ptTupUuid, usrUuid, relation, objectType, objectId, now],
        );
        materializedTuples.push({
          subjectType: "usr",
          subjectId: usrIdOf(usrUuid),
          relation,
          objectType,
          objectId,
        });
      }

      const { rows: invRows } = await c.query<InvRow>(
        `UPDATE inv SET status = 'accepted', terminal_at = $1, terminal_by = $2, invited_user_id = $2
         WHERE id = $3
         RETURNING id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by`,
        [now, usrUuid, inv.id],
      );
      return {
        invitation: rowToInv(invRows[0]!),
        membership: rowToMem(memRows[0]!),
        materializedTuples,
      };
    });
  }

  async declineInvitation(input: DeclineInvitationInput): Promise<Invitation> {
    return this.tx(async (c) => {
      const res = await c.query<InvRow>(
        `SELECT id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by
         FROM inv WHERE id = $1 FOR UPDATE`,
        [wireToUuid(input.invId)],
      );
      if (res.rows.length === 0) throw new NotFoundError(`Invitation ${input.invId} not found`);
      if (res.rows[0]!.status !== "pending") {
        throw new InvitationNotPendingError(
          `Invitation ${input.invId} is ${res.rows[0]!.status}`,
        );
      }
      const now = this.now();
      const terminalBy = input.asUsrId ? wireToUuid(input.asUsrId) : null;
      const { rows } = await c.query<InvRow>(
        `UPDATE inv SET status = 'declined', terminal_at = $1, terminal_by = $2 WHERE id = $3
         RETURNING id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by`,
        [now, terminalBy, res.rows[0]!.id],
      );
      return rowToInv(rows[0]!);
    });
  }

  async revokeInvitation(input: RevokeInvitationInput): Promise<Invitation> {
    return this.tx(async (c) => {
      const res = await c.query<InvRow>(
        `SELECT id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by
         FROM inv WHERE id = $1 FOR UPDATE`,
        [wireToUuid(input.invId)],
      );
      if (res.rows.length === 0) throw new NotFoundError(`Invitation ${input.invId} not found`);
      if (res.rows[0]!.status !== "pending") {
        throw new InvitationNotPendingError(
          `Invitation ${input.invId} is ${res.rows[0]!.status}`,
        );
      }
      const now = this.now();
      const { rows } = await c.query<InvRow>(
        `UPDATE inv SET status = 'revoked', terminal_at = $1, terminal_by = $2 WHERE id = $3
         RETURNING id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id, created_at, expires_at, terminal_at, terminal_by`,
        [now, wireToUuid(input.adminUsrId), res.rows[0]!.id],
      );
      return rowToInv(rows[0]!);
    });
  }

  // ─── Tuple accessors ───

  async listTuplesForSubject(
    subjectType: "usr",
    subjectId: UsrId,
  ): Promise<Tuple[]> {
    const { rows } = await this.pool.query<TupRow>(
      `SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
       FROM tup
       WHERE subject_type = $1 AND subject_id = $2`,
      [subjectType, wireToUuid(subjectId)],
    );
    return rows.map(rowToTup);
  }

  async listTuplesForObject(
    objectType: string,
    objectId: string,
    relation?: string,
  ): Promise<Tuple[]> {
    const params: unknown[] = [objectType, objectId];
    const conditions = ["object_type = $1", "object_id = $2"];
    if (relation !== undefined) {
      params.push(relation);
      conditions.push(`relation = $${params.length}`);
    }
    const { rows } = await this.pool.query<TupRow>(
      `SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
       FROM tup WHERE ${conditions.join(" AND ")}`,
      params,
    );
    return rows.map(rowToTup);
  }
}

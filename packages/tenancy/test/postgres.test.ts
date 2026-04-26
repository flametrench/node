// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decode, generate } from "@flametrench/ids";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  DuplicateMembershipError,
  InvitationNotPendingError,
  NotFoundError,
  RoleHierarchyError,
  SoleOwnerError,
  type UsrId,
} from "../src/index.js";
import { PostgresTenancyStore } from "../src/postgres.js";

const POSTGRES_URL = process.env.TENANCY_POSTGRES_URL;
const hasPostgres = Boolean(POSTGRES_URL);

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");

function newUsr(): UsrId {
  return generate("usr") as UsrId;
}

/**
 * Insert a `usr_` row. In production the identity layer owns this; for
 * tenancy integration tests we stand it in so FK constraints are satisfied.
 */
async function registerUser(pool: Pool, usrId: UsrId): Promise<void> {
  await pool.query(`INSERT INTO usr (id, status) VALUES ($1, 'active')`, [
    decode(usrId).uuid,
  ]);
}

describe.skipIf(!hasPostgres)("PostgresTenancyStore", () => {
  let pool: Pool;
  let store: PostgresTenancyStore;
  let alice: UsrId;
  let bob: UsrId;
  let carol: UsrId;

  beforeAll(async () => {
    pool = new Pool({ connectionString: POSTGRES_URL });
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    // Reset schema between tests for isolation.
    await pool.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
    await pool.query(SCHEMA_SQL);
    store = new PostgresTenancyStore(pool);
    alice = newUsr();
    bob = newUsr();
    carol = newUsr();
    // Pre-populate the usr table so mem FKs resolve. In production the
    // identity layer does this; @flametrench/tenancy only manages tenancy.
    await registerUser(pool, alice);
    await registerUser(pool, bob);
    await registerUser(pool, carol);
  });

  // ───── createOrg ─────

  it("creates an org + owner membership + membership tuple transactionally", async () => {
    const { org, ownerMembership } = await store.createOrg(alice);
    expect(org.status).toBe("active");
    expect(ownerMembership.role).toBe("owner");
    expect(ownerMembership.usrId).toBe(alice);
    const tuples = await store.listTuplesForSubject("usr", alice);
    expect(tuples).toHaveLength(1);
    expect(tuples[0]!.relation).toBe("owner");
    expect(tuples[0]!.objectType).toBe("org");
  });

  // ───── addMember ─────

  it("adds a member and creates the membership tuple", async () => {
    const { org } = await store.createOrg(alice);
    const mem = await store.addMember({
      orgId: org.id,
      usrId: bob,
      role: "member",
      invitedBy: alice,
    });
    expect(mem.role).toBe("member");
    expect(mem.invitedBy).toBe(alice);
    const tuples = await store.listTuplesForSubject("usr", bob);
    expect(tuples).toHaveLength(1);
  });

  it("rejects duplicate active memberships", async () => {
    const { org } = await store.createOrg(alice);
    await store.addMember({ orgId: org.id, usrId: bob, role: "member" });
    await expect(
      store.addMember({ orgId: org.id, usrId: bob, role: "admin" }),
    ).rejects.toThrow(DuplicateMembershipError);
  });

  // ───── changeRole ─────

  it("changeRole: replaces chain and tuple swap are atomic", async () => {
    const { org } = await store.createOrg(alice);
    const bobMem = await store.addMember({
      orgId: org.id,
      usrId: bob,
      role: "member",
    });
    const newMem = await store.changeRole({
      memId: bobMem.id,
      newRole: "admin",
    });
    expect(newMem.replaces).toBe(bobMem.id);
    expect(newMem.role).toBe("admin");
    const oldMem = await store.getMembership(bobMem.id);
    expect(oldMem.status).toBe("revoked");
    const tuples = await store.listTuplesForSubject("usr", bob);
    expect(tuples).toHaveLength(1);
    expect(tuples[0]!.relation).toBe("admin");
  });

  it("changeRole: refuses demoting the sole active owner", async () => {
    const { ownerMembership } = await store.createOrg(alice);
    await expect(
      store.changeRole({ memId: ownerMembership.id, newRole: "member" }),
    ).rejects.toThrow(SoleOwnerError);
  });

  // ───── suspend / reinstate ─────

  it("suspendMembership removes the tuple; reinstate restores it", async () => {
    const { org } = await store.createOrg(alice);
    const bobMem = await store.addMember({
      orgId: org.id,
      usrId: bob,
      role: "member",
    });
    await store.suspendMembership(bobMem.id);
    expect(await store.listTuplesForSubject("usr", bob)).toEqual([]);
    await store.reinstateMembership(bobMem.id);
    expect(await store.listTuplesForSubject("usr", bob)).toHaveLength(1);
  });

  // ───── selfLeave ─────

  it("selfLeave: non-owner leaves without transfer; removedBy is null", async () => {
    const { org } = await store.createOrg(alice);
    const bobMem = await store.addMember({
      orgId: org.id,
      usrId: bob,
      role: "member",
    });
    const left = await store.selfLeave({ memId: bobMem.id });
    expect(left.status).toBe("revoked");
    expect(left.removedBy).toBeNull();
  });

  it("selfLeave: sole-owner self-leave with transferTo atomically transfers + revokes", async () => {
    const { org, ownerMembership } = await store.createOrg(alice);
    await store.addMember({ orgId: org.id, usrId: bob, role: "member" });
    const left = await store.selfLeave({
      memId: ownerMembership.id,
      transferTo: bob,
    });
    expect(left.status).toBe("revoked");
    expect(await store.listTuplesForSubject("usr", alice)).toEqual([]);
    const bobTuples = await store.listTuplesForSubject("usr", bob);
    expect(bobTuples).toHaveLength(1);
    expect(bobTuples[0]!.relation).toBe("owner");
  });

  it("selfLeave: sole-owner self-leave without transferTo is rejected", async () => {
    const { ownerMembership } = await store.createOrg(alice);
    await expect(
      store.selfLeave({ memId: ownerMembership.id }),
    ).rejects.toThrow(SoleOwnerError);
  });

  // ───── adminRemove ─────

  it("adminRemove: removedBy is the admin's usr_id", async () => {
    const { org } = await store.createOrg(alice);
    const bobMem = await store.addMember({
      orgId: org.id,
      usrId: bob,
      role: "member",
    });
    const removed = await store.adminRemove({
      memId: bobMem.id,
      adminUsrId: alice,
    });
    expect(removed.removedBy).toBe(alice);
  });

  it("adminRemove: cannot remove an owner", async () => {
    const { ownerMembership, org } = await store.createOrg(alice);
    await store.addMember({ orgId: org.id, usrId: bob, role: "admin" });
    await expect(
      store.adminRemove({ memId: ownerMembership.id, adminUsrId: bob }),
    ).rejects.toThrow(RoleHierarchyError);
  });

  // ───── transferOwnership ─────

  it("transferOwnership atomically demotes owner + promotes target", async () => {
    const { org, ownerMembership } = await store.createOrg(alice);
    const bobMem = await store.addMember({
      orgId: org.id,
      usrId: bob,
      role: "admin",
    });
    const { fromMembership, toMembership } = await store.transferOwnership({
      orgId: org.id,
      fromMemId: ownerMembership.id,
      toMemId: bobMem.id,
    });
    expect(fromMembership.role).toBe("member");
    expect(toMembership.role).toBe("owner");

    const aliceTuples = await store.listTuplesForSubject("usr", alice);
    expect(aliceTuples.map((t) => t.relation)).toEqual(["member"]);
    const bobTuples = await store.listTuplesForSubject("usr", bob);
    expect(bobTuples.map((t) => t.relation)).toEqual(["owner"]);
  });

  // ───── Invitations ─────

  it("acceptInvitation materializes membership + pre-tuples in one transaction", async () => {
    const { org } = await store.createOrg(alice);
    const projectId = "0190f2a8-1b3c-7abc-8123-456789abcdef";
    const inv = await store.createInvitation({
      orgId: org.id,
      identifier: "carol@example.com",
      role: "guest",
      invitedBy: alice,
      expiresAt: new Date(Date.now() + 3600_000),
      preTuples: [
        { relation: "viewer", objectType: "proj", objectId: projectId },
      ],
    });
    const result = await store.acceptInvitation({
      invId: inv.id,
      asUsrId: carol,
      acceptingIdentifier: "carol@example.com",
    });
    expect(result.materializedTuples).toHaveLength(1);
    expect(result.invitation.status).toBe("accepted");
    expect(result.invitation.terminalBy).toBe(carol);
    const carolTuples = await store.listTuplesForSubject("usr", carol);
    expect(carolTuples).toHaveLength(2); // membership + pre-tuple
    const viewerTuple = carolTuples.find((t) => t.relation === "viewer");
    expect(viewerTuple?.objectId).toBe(projectId);
  });

  it("acceptInvitation: non-pending invitation is rejected", async () => {
    const { org } = await store.createOrg(alice);
    const inv = await store.createInvitation({
      orgId: org.id,
      identifier: "x@y",
      role: "member",
      invitedBy: alice,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    await store.acceptInvitation({
      invId: inv.id,
      asUsrId: bob,
      acceptingIdentifier: "x@y",
    });
    await expect(
      store.acceptInvitation({
        invId: inv.id,
        asUsrId: carol,
        acceptingIdentifier: "x@y",
      }),
    ).rejects.toThrow(InvitationNotPendingError);
  });

  it("declineInvitation transitions to declined", async () => {
    const { org } = await store.createOrg(alice);
    const inv = await store.createInvitation({
      orgId: org.id,
      identifier: "x@y",
      role: "member",
      invitedBy: alice,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    const declined = await store.declineInvitation({
      invId: inv.id,
      asUsrId: bob,
    });
    expect(declined.status).toBe("declined");
    expect(declined.terminalBy).toBe(bob);
  });

  it("revokeInvitation transitions to revoked", async () => {
    const { org } = await store.createOrg(alice);
    const inv = await store.createInvitation({
      orgId: org.id,
      identifier: "x@y",
      role: "member",
      invitedBy: alice,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    const revoked = await store.revokeInvitation({
      invId: inv.id,
      adminUsrId: alice,
    });
    expect(revoked.status).toBe("revoked");
    expect(revoked.terminalBy).toBe(alice);
  });

  // ───── Org revoke cascade ─────

  it("revokeOrg cascades: memberships revoked, tuples deleted", async () => {
    const { org } = await store.createOrg(alice);
    await store.addMember({ orgId: org.id, usrId: bob, role: "member" });
    await store.revokeOrg(org.id);
    expect((await store.getOrg(org.id)).status).toBe("revoked");
    expect(await store.listTuplesForSubject("usr", alice)).toEqual([]);
    expect(await store.listTuplesForSubject("usr", bob)).toEqual([]);
  });

  // ───── Listing ─────

  it("listMembers paginates", async () => {
    const { org } = await store.createOrg(alice);
    const extra1 = newUsr();
    const extra2 = newUsr();
    await registerUser(pool, extra1);
    await registerUser(pool, extra2);
    for (const u of [bob, carol, extra1, extra2]) {
      await store.addMember({ orgId: org.id, usrId: u, role: "member" });
    }
    const page1 = await store.listMembers(org.id, { limit: 2 });
    expect(page1.data).toHaveLength(2);
    expect(page1.nextCursor).not.toBeNull();
    const page2 = await store.listMembers(org.id, {
      limit: 10,
      cursor: page1.nextCursor!,
    });
    expect(page2.data.length).toBeGreaterThan(0);
    const allIds = [
      ...page1.data.map((m) => m.id),
      ...page2.data.map((m) => m.id),
    ];
    expect(new Set(allIds).size).toBe(5); // alice + 4 added
  });

  // ───── NotFound paths ─────

  it("getOrg / getMembership / getInvitation throw NotFoundError for unknown ids", async () => {
    await expect(store.getOrg(generate("org") as never)).rejects.toThrow(
      NotFoundError,
    );
    await expect(
      store.getMembership(generate("mem") as never),
    ).rejects.toThrow(NotFoundError);
    await expect(
      store.getInvitation(generate("inv") as never),
    ).rejects.toThrow(NotFoundError);
  });
});

if (!hasPostgres) {
  // eslint-disable-next-line no-console
  console.log(
    "[postgres.test.ts] TENANCY_POSTGRES_URL not set; PostgresTenancyStore tests are skipped.\n" +
      "  Set e.g. `TENANCY_POSTGRES_URL=postgresql://postgres:test@localhost:5432/flametrench_test` " +
      "with a reachable Postgres 16+ instance to run them.",
  );
}

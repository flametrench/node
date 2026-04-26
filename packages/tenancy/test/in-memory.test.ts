// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate } from "@flametrench/ids";
import { beforeEach, describe, expect, it } from "vitest";

import {
  DuplicateMembershipError,
  ForbiddenError,
  IdentifierBindingRequiredError,
  IdentifierMismatchError,
  InMemoryTenancyStore,
  InvitationExpiredError,
  InvitationNotPendingError,
  NotFoundError,
  PreconditionError,
  RoleHierarchyError,
  SoleOwnerError,
  type UsrId,
} from "../src/index.js";

// Deterministic-ish clock for tests. Advances by 1ms on each read so
// monotonic-timestamp assertions can distinguish events in the same test.
function makeClock(startMs = 1_700_000_000_000) {
  let t = startMs;
  return () => new Date(t++);
}

function newUsr(): UsrId {
  return generate("usr") as UsrId;
}

describe("InMemoryTenancyStore", () => {
  let store: InMemoryTenancyStore;
  let alice: UsrId;
  let bob: UsrId;
  let carol: UsrId;
  let dave: UsrId;

  beforeEach(() => {
    store = new InMemoryTenancyStore({ clock: makeClock() });
    alice = newUsr();
    bob = newUsr();
    carol = newUsr();
    dave = newUsr();
  });

  // ───────────── Organizations ─────────────

  describe("createOrg", () => {
    it("creates an org with an active status and the creator as owner", async () => {
      const { org, ownerMembership } = await store.createOrg(alice);
      expect(org.status).toBe("active");
      expect(ownerMembership.usrId).toBe(alice);
      expect(ownerMembership.orgId).toBe(org.id);
      expect(ownerMembership.role).toBe("owner");
      expect(ownerMembership.status).toBe("active");
      expect(ownerMembership.replaces).toBeNull();
      expect(ownerMembership.invitedBy).toBeNull();
      expect(ownerMembership.removedBy).toBeNull();
    });

    it("materializes the membership tuple on creation", async () => {
      const { org } = await store.createOrg(alice);
      const tuples = await store.listTuplesForSubject("usr", alice);
      expect(tuples).toEqual([
        {
          subjectType: "usr",
          subjectId: alice,
          relation: "owner",
          objectType: "org",
          objectId: org.id,
        },
      ]);
    });
  });

  describe("getOrg", () => {
    it("returns a created org", async () => {
      const { org } = await store.createOrg(alice);
      expect(await store.getOrg(org.id)).toEqual(org);
    });

    it("throws NotFoundError for unknown org ids", async () => {
      await expect(store.getOrg("org_nonexistent" as never)).rejects.toThrow(
        NotFoundError,
      );
    });
  });

  describe("org lifecycle", () => {
    it("suspends and reinstates orgs", async () => {
      const { org } = await store.createOrg(alice);
      const suspended = await store.suspendOrg(org.id);
      expect(suspended.status).toBe("suspended");
      const reinstated = await store.reinstateOrg(org.id);
      expect(reinstated.status).toBe("active");
    });

    it("revoke cascades: all active memberships are revoked and tuples removed", async () => {
      const { org } = await store.createOrg(alice);
      await store.addMember({ orgId: org.id, usrId: bob, role: "member" });
      await store.revokeOrg(org.id);
      expect((await store.getOrg(org.id)).status).toBe("revoked");
      expect(await store.listTuplesForSubject("usr", alice)).toEqual([]);
      expect(await store.listTuplesForSubject("usr", bob)).toEqual([]);
      const page = await store.listMembers(org.id);
      for (const m of page.data) expect(m.status).toBe("revoked");
    });

    it("refuses double-revocation", async () => {
      const { org } = await store.createOrg(alice);
      await store.revokeOrg(org.id);
      await expect(store.revokeOrg(org.id)).rejects.toThrow();
    });
  });

  // ───────────── Memberships ─────────────

  describe("addMember", () => {
    it("adds a member and materializes the tuple", async () => {
      const { org } = await store.createOrg(alice);
      const mem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "member",
        invitedBy: alice,
      });
      expect(mem.usrId).toBe(bob);
      expect(mem.role).toBe("member");
      expect(mem.invitedBy).toBe(alice);
      const tuples = await store.listTuplesForSubject("usr", bob);
      expect(tuples).toHaveLength(1);
      expect(tuples[0]!.relation).toBe("member");
    });

    it("rejects duplicate active memberships", async () => {
      const { org } = await store.createOrg(alice);
      await store.addMember({ orgId: org.id, usrId: bob, role: "member" });
      await expect(
        store.addMember({ orgId: org.id, usrId: bob, role: "admin" }),
      ).rejects.toThrow(DuplicateMembershipError);
    });

    it("rejects adding to a non-active org", async () => {
      const { org } = await store.createOrg(alice);
      await store.suspendOrg(org.id);
      await expect(
        store.addMember({ orgId: org.id, usrId: bob, role: "member" }),
      ).rejects.toThrow(PreconditionError);
    });
  });

  describe("changeRole (revoke + re-add)", () => {
    it("creates a new mem with replaces pointing at the old, and swaps tuples", async () => {
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
      expect(newMem.id).not.toBe(bobMem.id);
      expect(newMem.replaces).toBe(bobMem.id);
      expect(newMem.role).toBe("admin");
      expect(newMem.status).toBe("active");

      // Old membership is revoked; new is active; tuple reflects new role.
      const revokedOld = await store.getMembership(bobMem.id);
      expect(revokedOld.status).toBe("revoked");
      const tuples = await store.listTuplesForSubject("usr", bob);
      expect(tuples).toHaveLength(1);
      expect(tuples[0]!.relation).toBe("admin");
    });

    it("preserves invitedBy across the chain", async () => {
      const { org } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "member",
        invitedBy: alice,
      });
      const updated = await store.changeRole({
        memId: bobMem.id,
        newRole: "admin",
      });
      expect(updated.invitedBy).toBe(alice);
    });

    it("refuses demoting the sole active owner", async () => {
      const { ownerMembership } = await store.createOrg(alice);
      await expect(
        store.changeRole({ memId: ownerMembership.id, newRole: "member" }),
      ).rejects.toThrow(SoleOwnerError);
    });

    it("allows demoting an owner when another owner exists", async () => {
      const { org, ownerMembership } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "member",
      });
      await store.changeRole({ memId: bobMem.id, newRole: "owner" });
      // Now two owners; demote Alice.
      const demoted = await store.changeRole({
        memId: ownerMembership.id,
        newRole: "member",
      });
      expect(demoted.role).toBe("member");
    });
  });

  describe("suspend / reinstate membership", () => {
    it("suspends an active member and removes the tuple; reinstating restores it", async () => {
      const { org } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "member",
      });
      const suspended = await store.suspendMembership(bobMem.id);
      expect(suspended.status).toBe("suspended");
      expect(await store.listTuplesForSubject("usr", bob)).toEqual([]);
      const reinstated = await store.reinstateMembership(bobMem.id);
      expect(reinstated.status).toBe("active");
      expect(await store.listTuplesForSubject("usr", bob)).toHaveLength(1);
    });

    it("refuses to suspend the sole owner", async () => {
      const { ownerMembership } = await store.createOrg(alice);
      await expect(
        store.suspendMembership(ownerMembership.id),
      ).rejects.toThrow(SoleOwnerError);
    });
  });

  // ───────────── Self-leave ─────────────

  describe("selfLeave", () => {
    it("lets a non-owner leave", async () => {
      const { org } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "member",
      });
      const left = await store.selfLeave({ memId: bobMem.id });
      expect(left.status).toBe("revoked");
      expect(left.removedBy).toBeNull();
      expect(await store.listTuplesForSubject("usr", bob)).toEqual([]);
    });

    it("lets a non-sole owner leave without transferTo", async () => {
      const { org, ownerMembership } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "member",
      });
      await store.changeRole({ memId: bobMem.id, newRole: "owner" });
      const left = await store.selfLeave({ memId: ownerMembership.id });
      expect(left.status).toBe("revoked");
    });

    it("refuses when the leaver is the sole owner and no transferTo is given", async () => {
      const { ownerMembership } = await store.createOrg(alice);
      await expect(
        store.selfLeave({ memId: ownerMembership.id }),
      ).rejects.toThrow(SoleOwnerError);
    });

    it("atomically transfers ownership and revokes when sole owner supplies transferTo", async () => {
      const { org, ownerMembership } = await store.createOrg(alice);
      await store.addMember({ orgId: org.id, usrId: bob, role: "member" });
      const left = await store.selfLeave({
        memId: ownerMembership.id,
        transferTo: bob,
      });
      expect(left.status).toBe("revoked");
      // Alice's tuple is gone.
      expect(await store.listTuplesForSubject("usr", alice)).toEqual([]);
      // Bob is now owner.
      const bobTuples = await store.listTuplesForSubject("usr", bob);
      expect(bobTuples).toHaveLength(1);
      expect(bobTuples[0]!.relation).toBe("owner");
    });

    it("rejects transferTo pointing at a user without an active membership", async () => {
      const { ownerMembership } = await store.createOrg(alice);
      await expect(
        store.selfLeave({ memId: ownerMembership.id, transferTo: bob }),
      ).rejects.toThrow(NotFoundError);
    });
  });

  // ───────────── Admin-remove ─────────────

  describe("adminRemove", () => {
    it("lets an owner remove a lower-role member, setting removedBy", async () => {
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
      expect(removed.status).toBe("revoked");
      expect(removed.removedBy).toBe(alice);
      expect(await store.listTuplesForSubject("usr", bob)).toEqual([]);
    });

    it("refuses non-admin callers", async () => {
      const { org } = await store.createOrg(alice);
      await store.addMember({ orgId: org.id, usrId: bob, role: "member" });
      const carolMem = await store.addMember({
        orgId: org.id,
        usrId: carol,
        role: "guest",
      });
      await expect(
        store.adminRemove({ memId: carolMem.id, adminUsrId: bob }),
      ).rejects.toThrow(ForbiddenError);
    });

    it("permits an admin to remove a peer admin (rank tie is allowed; rank < is not)", async () => {
      const { org } = await store.createOrg(alice);
      await store.addMember({ orgId: org.id, usrId: bob, role: "admin" });
      const carolMem = await store.addMember({
        orgId: org.id,
        usrId: carol,
        role: "admin",
      });
      const removed = await store.adminRemove({
        memId: carolMem.id,
        adminUsrId: bob,
      });
      expect(removed.status).toBe("revoked");
      expect(removed.removedBy).toBe(bob);
    });

    it("refuses removal of an owner (must go via transferOwnership)", async () => {
      const { org, ownerMembership } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "admin",
      });
      await expect(
        store.adminRemove({ memId: ownerMembership.id, adminUsrId: bob }),
      ).rejects.toThrow(RoleHierarchyError);
    });
  });

  // ───────────── transferOwnership ─────────────

  describe("transferOwnership", () => {
    it("atomically demotes old owner to member and promotes target to owner", async () => {
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
      expect(toMembership.role).toBe("owner");
      expect(toMembership.usrId).toBe(bob);
      expect(fromMembership.role).toBe("member");
      expect(fromMembership.usrId).toBe(alice);

      // Tuple table matches.
      const aliceTuples = await store.listTuplesForSubject("usr", alice);
      expect(aliceTuples).toHaveLength(1);
      expect(aliceTuples[0]!.relation).toBe("member");
      const bobTuples = await store.listTuplesForSubject("usr", bob);
      expect(bobTuples).toHaveLength(1);
      expect(bobTuples[0]!.relation).toBe("owner");
    });

    it("refuses if the 'from' membership is not an owner", async () => {
      const { org, ownerMembership } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "admin",
      });
      const carolMem = await store.addMember({
        orgId: org.id,
        usrId: carol,
        role: "member",
      });
      // Non-owner trying to transfer ownership.
      await expect(
        store.transferOwnership({
          orgId: org.id,
          fromMemId: bobMem.id,
          toMemId: carolMem.id,
        }),
      ).rejects.toThrow(PreconditionError);
      // And using the actual owner works.
      const { toMembership } = await store.transferOwnership({
        orgId: org.id,
        fromMemId: ownerMembership.id,
        toMemId: carolMem.id,
      });
      expect(toMembership.role).toBe("owner");
    });

    it("refuses self-transfer", async () => {
      const { org, ownerMembership } = await store.createOrg(alice);
      await expect(
        store.transferOwnership({
          orgId: org.id,
          fromMemId: ownerMembership.id,
          toMemId: ownerMembership.id,
        }),
      ).rejects.toThrow();
    });
  });

  // ───────────── Invitations ─────────────

  describe("createInvitation", () => {
    it("creates an invitation in pending state", async () => {
      const { org } = await store.createOrg(alice);
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "carol@example.com",
        role: "member",
        invitedBy: alice,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      expect(inv.status).toBe("pending");
      expect(inv.preTuples).toEqual([]);
      expect(inv.terminalAt).toBeNull();
      expect(inv.terminalBy).toBeNull();
    });

    it("refuses past expiration", async () => {
      const { org } = await store.createOrg(alice);
      await expect(
        store.createInvitation({
          orgId: org.id,
          identifier: "x@y",
          role: "member",
          invitedBy: alice,
          expiresAt: new Date(0),
        }),
      ).rejects.toThrow(PreconditionError);
    });
  });

  describe("acceptInvitation", () => {
    it("creates a membership, materializes the tuple, and transitions the invitation", async () => {
      const { org } = await store.createOrg(alice);
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "bob@example.com",
        role: "member",
        invitedBy: alice,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      const result = await store.acceptInvitation({
        invId: inv.id,
        asUsrId: bob,
        acceptingIdentifier: "bob@example.com",
      });
      expect(result.membership.usrId).toBe(bob);
      expect(result.membership.role).toBe("member");
      expect(result.membership.invitedBy).toBe(alice);
      expect(result.invitation.status).toBe("accepted");
      expect(result.invitation.invitedUserId).toBe(bob);
      expect(result.invitation.terminalBy).toBe(bob);
      expect(result.materializedTuples).toEqual([]);
      const tuples = await store.listTuplesForSubject("usr", bob);
      expect(tuples).toHaveLength(1);
      expect(tuples[0]!.relation).toBe("member");
    });

    it("materializes preTuples atomically with the membership", async () => {
      const { org } = await store.createOrg(alice);
      const projectId = "0190f2a8-1b3c-7abc-8123-456789abcdef";
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "carol@example.com",
        role: "guest",
        invitedBy: alice,
        expiresAt: new Date(Date.now() + 3600_000),
        preTuples: [
          { relation: "viewer", objectType: "project", objectId: projectId },
        ],
      });
      const result = await store.acceptInvitation({
        invId: inv.id,
        asUsrId: carol,
        acceptingIdentifier: "carol@example.com",
      });
      expect(result.materializedTuples).toHaveLength(1);
      const tuples = await store.listTuplesForSubject("usr", carol);
      expect(tuples).toHaveLength(2);
      const viewerTuple = tuples.find((t) => t.relation === "viewer");
      expect(viewerTuple).toEqual({
        subjectType: "usr",
        subjectId: carol,
        relation: "viewer",
        objectType: "project",
        objectId: projectId,
      });
    });

    it("generates a usr_id when asUsrId is absent", async () => {
      const { org } = await store.createOrg(alice);
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "new@example.com",
        role: "member",
        invitedBy: alice,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      const result = await store.acceptInvitation({ invId: inv.id });
      expect(result.membership.usrId).toMatch(/^usr_[0-9a-f]{32}$/);
      expect(result.invitation.invitedUserId).toBe(result.membership.usrId);
    });

    it("refuses a non-pending invitation", async () => {
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

    it("refuses an expired invitation", async () => {
      const clockMs = 1_700_000_000_000;
      const frozen = new InMemoryTenancyStore({
        clock: () => new Date(clockMs),
      });
      const { org } = await frozen.createOrg(alice);
      const inv = await frozen.createInvitation({
        orgId: org.id,
        identifier: "x@y",
        role: "member",
        invitedBy: alice,
        expiresAt: new Date(clockMs + 1000),
      });
      // Advance clock past expiry using a fresh store with a different clock.
      // (For the in-memory store, expiry is evaluated at acceptInvitation
      //  call-time against now(), so we need the clock to return a value
      //  past the invitation's expiresAt.)
      const later = new InMemoryTenancyStore({
        clock: () => new Date(clockMs + 10_000),
      });
      // Migrate the invitation into the later-clock store via a direct
      // test-only approach: since InMemoryTenancyStore holds state on the
      // instance, we instead simulate expiry by creating an invitation with
      // a very-near-future expiresAt and letting the default clock advance.
      void later;
      // Simpler and more direct: use the real store to issue an expired
      // invitation by mutating via the public API after time progression.
      // The easiest way: issue an invitation with a 0-delay expiry and then
      // advance now() via the test clock (our makeClock advances +1ms per
      // tick). Given clock advances 1ms on each call, the invitation's
      // expiresAt of clockMs+1000 is reached after 1000 clock reads. Simpler
      // to just use Date(0) which is always in the past... but that's
      // rejected at creation.

      // Pragmatic approach: use a very short TTL and many clock ticks.
      const shortClock = makeClock();
      const shortStore = new InMemoryTenancyStore({ clock: shortClock });
      const { org: o2 } = await shortStore.createOrg(alice);
      const inv2 = await shortStore.createInvitation({
        orgId: o2.id,
        identifier: "x@y",
        role: "member",
        invitedBy: alice,
        // 50ms in the future from the clock's current value (which is fetched by now()).
        expiresAt: new Date(shortClock().getTime() + 50),
      });
      // Burn ~200 ticks to push the clock past expiresAt.
      for (let i = 0; i < 200; i++) shortClock();
      await expect(
        shortStore.acceptInvitation({
          invId: inv2.id,
          asUsrId: bob,
          acceptingIdentifier: "x@y",
        }),
      ).rejects.toThrow(InvitationExpiredError);
      // Silence unused var warnings for the earlier incomplete code paths.
      void inv;
      void frozen;
    });

    it("refuses when the invitee already has an active membership", async () => {
      const { org } = await store.createOrg(alice);
      await store.addMember({ orgId: org.id, usrId: bob, role: "member" });
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "bob@example.com",
        role: "admin",
        invitedBy: alice,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      await expect(
        store.acceptInvitation({
          invId: inv.id,
          asUsrId: bob,
          acceptingIdentifier: "bob@example.com",
        }),
      ).rejects.toThrow(DuplicateMembershipError);
    });

    it("(ADR 0009) requires acceptingIdentifier when asUsrId is provided", async () => {
      const { org } = await store.createOrg(alice);
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "bob@example.com",
        role: "member",
        invitedBy: alice,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      await expect(
        store.acceptInvitation({ invId: inv.id, asUsrId: bob }),
      ).rejects.toThrow(IdentifierBindingRequiredError);
    });

    it("(ADR 0009) rejects mismatched acceptingIdentifier (privilege-escalation closer)", async () => {
      const { org } = await store.createOrg(alice);
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "victim@example.org",
        role: "owner",
        invitedBy: alice,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      await expect(
        store.acceptInvitation({
          invId: inv.id,
          asUsrId: bob,
          acceptingIdentifier: "attacker@example.com",
        }),
      ).rejects.toThrow(IdentifierMismatchError);
    });
  });

  describe("declineInvitation", () => {
    it("transitions the invitation to declined with the invitee attributed", async () => {
      const { org } = await store.createOrg(alice);
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "bob@example.com",
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

    it("allows anonymous decline (terminalBy null)", async () => {
      const { org } = await store.createOrg(alice);
      const inv = await store.createInvitation({
        orgId: org.id,
        identifier: "x@y",
        role: "member",
        invitedBy: alice,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      const declined = await store.declineInvitation({ invId: inv.id });
      expect(declined.terminalBy).toBeNull();
    });
  });

  describe("revokeInvitation", () => {
    it("transitions the invitation to revoked with the admin attributed", async () => {
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
  });

  // ───────────── Listing + pagination ─────────────

  describe("listMembers", () => {
    it("paginates via UUID-ordered cursor", async () => {
      const { org } = await store.createOrg(alice);
      for (const u of [bob, carol, dave]) {
        await store.addMember({ orgId: org.id, usrId: u, role: "member" });
      }
      const page1 = await store.listMembers(org.id, { limit: 2 });
      expect(page1.data).toHaveLength(2);
      expect(page1.nextCursor).not.toBeNull();
      const page2 = await store.listMembers(org.id, {
        limit: 2,
        cursor: page1.nextCursor!,
      });
      expect(page2.data.length).toBeGreaterThan(0);
      expect(page2.nextCursor).toBeNull();
      const seen = new Set([
        ...page1.data.map((m) => m.id),
        ...page2.data.map((m) => m.id),
      ]);
      expect(seen.size).toBe(4); // Alice + three added
    });

    it("filters by status", async () => {
      const { org } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "member",
      });
      await store.suspendMembership(bobMem.id);
      const active = await store.listMembers(org.id, { status: "active" });
      expect(active.data.map((m) => m.usrId)).toEqual([alice]);
      const suspended = await store.listMembers(org.id, {
        status: "suspended",
      });
      expect(suspended.data.map((m) => m.usrId)).toEqual([bob]);
    });
  });

  // ───────────── Tuple accessors ─────────────

  describe("tuple accessors", () => {
    it("listTuplesForObject enumerates who holds a relation on an object", async () => {
      const { org } = await store.createOrg(alice);
      await store.addMember({ orgId: org.id, usrId: bob, role: "admin" });
      await store.addMember({ orgId: org.id, usrId: carol, role: "member" });
      const admins = await store.listTuplesForObject("org", org.id, "admin");
      expect(admins.map((t) => t.subjectId)).toEqual([bob]);
      const all = await store.listTuplesForObject("org", org.id);
      expect(all).toHaveLength(3); // owner, admin, member
    });
  });

  // ───────────── Audit attribution ─────────────

  describe("removedBy attribution", () => {
    it("is null for self-leave, non-null for admin-remove", async () => {
      const { org } = await store.createOrg(alice);
      const bobMem = await store.addMember({
        orgId: org.id,
        usrId: bob,
        role: "member",
      });
      const carolMem = await store.addMember({
        orgId: org.id,
        usrId: carol,
        role: "member",
      });
      const self = await store.selfLeave({ memId: bobMem.id });
      expect(self.removedBy).toBeNull();
      const removed = await store.adminRemove({
        memId: carolMem.id,
        adminUsrId: alice,
      });
      expect(removed.removedBy).toBe(alice);
    });
  });
});

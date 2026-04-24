// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate } from "@flametrench/ids";
import { beforeEach, describe, expect, it } from "vitest";

import {
  DuplicateTupleError,
  EmptyRelationSetError,
  InMemoryTupleStore,
  InvalidFormatError,
  TupleNotFoundError,
  type UsrId,
} from "../src/index.js";

function newUsr(): UsrId {
  return generate("usr") as UsrId;
}

function newOrgId(): string {
  return generate("org");
}

function newProjectId(): string {
  // Project is an application-custom object type, so we use a bare UUID
  // (not a Flametrench-prefixed ID) to match how apps model their own
  // domain objects in tuples.
  return generate("org").slice(4); // reuse UUID hex from a generated id
}

describe("InMemoryTupleStore", () => {
  let store: InMemoryTupleStore;
  let alice: UsrId;
  let bob: UsrId;
  let carol: UsrId;
  let orgAcme: string;
  let project42: string;

  beforeEach(() => {
    store = new InMemoryTupleStore();
    alice = newUsr();
    bob = newUsr();
    carol = newUsr();
    orgAcme = newOrgId();
    project42 = newProjectId();
  });

  // ───── createTuple ─────

  describe("createTuple", () => {
    it("creates a tuple and returns it with a fresh tup_ id", async () => {
      const t = await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "owner",
        objectType: "org",
        objectId: orgAcme,
        createdBy: alice,
      });
      expect(t.id).toMatch(/^tup_[0-9a-f]{32}$/);
      expect(t.subjectId).toBe(alice);
      expect(t.createdBy).toBe(alice);
    });

    it("rejects a duplicate natural key with the existing tuple id attached", async () => {
      const first = await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      try {
        await store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "proj",
          objectId: project42,
        });
        throw new Error("expected DuplicateTupleError");
      } catch (e) {
        expect(e).toBeInstanceOf(DuplicateTupleError);
        expect((e as DuplicateTupleError).existingTupleId).toBe(first.id);
      }
    });

    it("rejects invalid relation names", async () => {
      await expect(
        store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "Owner", // uppercase not permitted
          objectType: "org",
          objectId: orgAcme,
        }),
      ).rejects.toThrow(InvalidFormatError);
    });

    it("rejects invalid object type prefixes", async () => {
      await expect(
        store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "viewer",
          objectType: "UPPER", // pattern requires lowercase
          objectId: project42,
        }),
      ).rejects.toThrow(InvalidFormatError);
    });

    it("accepts custom (non-built-in) relations matching the regex", async () => {
      const t = await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "dispatcher",
        objectType: "org",
        objectId: orgAcme,
      });
      expect(t.relation).toBe("dispatcher");
    });
  });

  // ───── check() exact-match ─────

  describe("check (exact-match)", () => {
    beforeEach(async () => {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "proj",
        objectId: project42,
      });
    });

    it("returns allowed=true and the matched tup id for an exact-match hit", async () => {
      const result = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "proj",
        objectId: project42,
      });
      expect(result.allowed).toBe(true);
      expect(result.matchedTupleId).toMatch(/^tup_/);
    });

    it("returns allowed=false for a different relation on the same object", async () => {
      const result = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      expect(result.allowed).toBe(false);
      expect(result.matchedTupleId).toBeNull();
    });

    it("returns allowed=false for a different subject", async () => {
      const result = await store.check({
        subjectType: "usr",
        subjectId: bob,
        relation: "editor",
        objectType: "proj",
        objectId: project42,
      });
      expect(result.allowed).toBe(false);
    });

    it("returns allowed=false for a different object", async () => {
      const result = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "proj",
        objectId: newProjectId(),
      });
      expect(result.allowed).toBe(false);
    });
  });

  // ───── No-derivation invariant ─────

  describe("no-derivation invariant (ADR 0001 load-bearing)", () => {
    it("admin does not imply editor", async () => {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "admin",
        objectType: "org",
        objectId: orgAcme,
      });
      const editorCheck = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "org",
        objectId: orgAcme,
      });
      expect(editorCheck.allowed).toBe(false);
    });

    it("editor does not imply viewer", async () => {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "proj",
        objectId: project42,
      });
      const viewerCheck = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      expect(viewerCheck.allowed).toBe(false);
    });

    it("membership does NOT imply anything on org-owned objects (no parent-child inheritance)", async () => {
      // Alice is a member of org_acme.
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "member",
        objectType: "org",
        objectId: orgAcme,
      });
      // project_42 is application-owned by org_acme, but authz doesn't
      // know that relationship; there's no tuple granting Alice anything
      // on project_42. check() MUST return false.
      const projectCheck = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      expect(projectCheck.allowed).toBe(false);
    });
  });

  // ───── checkAny (set form) ─────

  describe("checkAny (set form)", () => {
    beforeEach(async () => {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "proj",
        objectId: project42,
      });
    });

    it("returns allowed=true if any requested relation matches", async () => {
      const result = await store.checkAny({
        subjectType: "usr",
        subjectId: alice,
        relations: ["viewer", "editor", "owner"],
        objectType: "proj",
        objectId: project42,
      });
      expect(result.allowed).toBe(true);
    });

    it("returns allowed=false if none of the requested relations match", async () => {
      const result = await store.checkAny({
        subjectType: "usr",
        subjectId: alice,
        relations: ["viewer", "admin"],
        objectType: "proj",
        objectId: project42,
      });
      expect(result.allowed).toBe(false);
    });

    it("rejects an empty relation set", async () => {
      await expect(
        store.checkAny({
          subjectType: "usr",
          subjectId: alice,
          relations: [],
          objectType: "proj",
          objectId: project42,
        }),
      ).rejects.toThrow(EmptyRelationSetError);
    });

    it("equivalent to single-relation check when relations has length 1", async () => {
      const single = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "proj",
        objectId: project42,
      });
      const set = await store.checkAny({
        subjectType: "usr",
        subjectId: alice,
        relations: ["editor"],
        objectType: "proj",
        objectId: project42,
      });
      expect(single.allowed).toBe(set.allowed);
      expect(single.matchedTupleId).toBe(set.matchedTupleId);
    });
  });

  // ───── deleteTuple ─────

  describe("deleteTuple", () => {
    it("removes a tuple and its natural-key index entry", async () => {
      const t = await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      await store.deleteTuple(t.id);
      const check = await store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      expect(check.allowed).toBe(false);
      // And the natural-key slot is free for re-creation.
      const recreated = await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "viewer",
        objectType: "proj",
        objectId: project42,
      });
      expect(recreated.id).not.toBe(t.id);
    });

    it("throws TupleNotFoundError for unknown ids", async () => {
      await expect(
        store.deleteTuple("tup_deadbeef00000000000000000000ff" as never),
      ).rejects.toThrow(TupleNotFoundError);
    });
  });

  // ───── cascadeRevokeSubject ─────

  describe("cascadeRevokeSubject", () => {
    it("deletes every tuple held by a subject and returns the count", async () => {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "owner",
        objectType: "org",
        objectId: orgAcme,
      });
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "proj",
        objectId: project42,
      });
      await store.createTuple({
        subjectType: "usr",
        subjectId: bob,
        relation: "member",
        objectType: "org",
        objectId: orgAcme,
      });

      const n = await store.cascadeRevokeSubject("usr", alice);
      expect(n).toBe(2);
      const alicePage = await store.listTuplesBySubject("usr", alice);
      expect(alicePage.data).toHaveLength(0);
      // Bob is untouched.
      const bobPage = await store.listTuplesBySubject("usr", bob);
      expect(bobPage.data).toHaveLength(1);
    });
  });

  // ───── Listing + pagination ─────

  describe("listing + pagination", () => {
    beforeEach(async () => {
      for (const u of [alice, bob, carol]) {
        await store.createTuple({
          subjectType: "usr",
          subjectId: u,
          relation: "viewer",
          objectType: "proj",
          objectId: project42,
        });
      }
    });

    it("listTuplesByObject filters by relation", async () => {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "editor",
        objectType: "proj",
        objectId: project42,
      });
      const viewers = await store.listTuplesByObject(
        "proj",
        project42,
        "viewer",
      );
      expect(viewers.data).toHaveLength(3);
      const all = await store.listTuplesByObject("proj", project42);
      expect(all.data).toHaveLength(4);
    });

    it("listTuplesByObject paginates via tup_id cursor", async () => {
      const page1 = await store.listTuplesByObject(
        "proj",
        project42,
        "viewer",
        { limit: 2 },
      );
      expect(page1.data).toHaveLength(2);
      expect(page1.nextCursor).not.toBeNull();
      const page2 = await store.listTuplesByObject(
        "proj",
        project42,
        "viewer",
        { limit: 2, cursor: page1.nextCursor! },
      );
      expect(page2.data).toHaveLength(1);
      expect(page2.nextCursor).toBeNull();
    });

    it("listTuplesBySubject returns only that subject's tuples", async () => {
      const alicesTuples = await store.listTuplesBySubject("usr", alice);
      expect(alicesTuples.data).toHaveLength(1);
      expect(alicesTuples.data[0]!.subjectId).toBe(alice);
    });
  });

  // ───── Uniqueness fixture ─────

  describe("uniqueness (spec conformance)", () => {
    it("rejects creation of two tuples with identical natural keys", async () => {
      await store.createTuple({
        subjectType: "usr",
        subjectId: alice,
        relation: "owner",
        objectType: "org",
        objectId: orgAcme,
      });
      await expect(
        store.createTuple({
          subjectType: "usr",
          subjectId: alice,
          relation: "owner",
          objectType: "org",
          objectId: orgAcme,
        }),
      ).rejects.toThrow(DuplicateTupleError);
    });
  });
});

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate } from "@flametrench/ids";
import { beforeEach, describe, expect, it } from "vitest";

import {
  InMemoryShareStore,
  InvalidFormatError,
  InvalidShareTokenError,
  SHARE_MAX_TTL_SECONDS,
  ShareConsumedError,
  ShareExpiredError,
  ShareNotFoundError,
  ShareRevokedError,
  type ShrId,
  type UsrId,
} from "../src/index.js";

describe("InMemoryShareStore", () => {
  let store: InMemoryShareStore;
  let alice: UsrId;
  let project42: string;

  beforeEach(() => {
    store = new InMemoryShareStore();
    alice = generate("usr") as UsrId;
    project42 = generate("usr").slice(4); // bare uuid hex
  });

  // ─── createShare / getShare ───

  it("createShare yields a fresh shr_ id and a token distinct from it", async () => {
    const result = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    expect(result.share.id).toMatch(/^shr_[0-9a-f]{32}$/);
    expect(result.token).not.toBe(result.share.id);
    expect(result.token.length).toBeGreaterThan(20);
    expect(result.share.singleUse).toBe(false);
    expect(result.share.consumedAt).toBeNull();
    expect(result.share.revokedAt).toBeNull();
  });

  it("getShare round-trips the public record", async () => {
    const { share } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const fetched = await store.getShare(share.id);
    expect(fetched.id).toBe(share.id);
    expect(fetched.objectId).toBe(project42);
  });

  it("getShare raises ShareNotFoundError for unknown ids", async () => {
    await expect(store.getShare(generate("shr") as ShrId)).rejects.toThrow(
      ShareNotFoundError,
    );
  });

  it("rejects malformed relation", async () => {
    await expect(
      store.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "Viewer!",
        createdBy: alice,
        expiresInSeconds: 600,
      }),
    ).rejects.toThrow(InvalidFormatError);
  });

  it("rejects malformed object_type", async () => {
    await expect(
      store.createShare({
        objectType: "Project",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: 600,
      }),
    ).rejects.toThrow(InvalidFormatError);
  });

  it("rejects negative expiresInSeconds", async () => {
    await expect(
      store.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: -1,
      }),
    ).rejects.toThrow(InvalidFormatError);
  });

  it("rejects expiresInSeconds beyond the 365-day ceiling", async () => {
    await expect(
      store.createShare({
        objectType: "proj",
        objectId: project42,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: SHARE_MAX_TTL_SECONDS + 1,
      }),
    ).rejects.toThrow(InvalidFormatError);
  });

  // ─── verifyShareToken ───

  it("verifyShareToken returns the share + relation for a valid token", async () => {
    const { share, token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const v = await store.verifyShareToken(token);
    expect(v.shareId).toBe(share.id);
    expect(v.objectType).toBe("proj");
    expect(v.objectId).toBe(project42);
    expect(v.relation).toBe("viewer");
  });

  it("verifyShareToken with a junk token raises InvalidShareTokenError", async () => {
    await expect(store.verifyShareToken("not-a-token")).rejects.toThrow(
      InvalidShareTokenError,
    );
  });

  it("verifyShareToken on a revoked share raises ShareRevokedError", async () => {
    const { share, token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    await store.revokeShare(share.id);
    await expect(store.verifyShareToken(token)).rejects.toThrow(
      ShareRevokedError,
    );
  });

  it("verifyShareToken on an expired share raises ShareExpiredError", async () => {
    let now = new Date("2026-04-27T00:00:00Z");
    const clock = () => now;
    const s = new InMemoryShareStore({ clock });
    const { token } = await s.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 60,
    });
    now = new Date(now.getTime() + 61 * 1000);
    await expect(s.verifyShareToken(token)).rejects.toThrow(ShareExpiredError);
  });

  // ─── single_use semantics ───

  it("single-use share consumes on first verify and rejects subsequent verifies", async () => {
    const { token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
      singleUse: true,
    });
    const first = await store.verifyShareToken(token);
    expect(first.relation).toBe("viewer");
    await expect(store.verifyShareToken(token)).rejects.toThrow(
      ShareConsumedError,
    );
  });

  it("single-use consumed_at is set on the public record after verify", async () => {
    const { share, token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
      singleUse: true,
    });
    expect(share.consumedAt).toBeNull();
    await store.verifyShareToken(token);
    const after = await store.getShare(share.id);
    expect(after.consumedAt).not.toBeNull();
  });

  it("non-single-use shares can be verified repeatedly", async () => {
    const { token } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    await store.verifyShareToken(token);
    const second = await store.verifyShareToken(token);
    expect(second.relation).toBe("viewer");
  });

  // ─── error precedence: revoked > consumed > expired ───

  it("revoked + expired share raises ShareRevokedError (revoke wins)", async () => {
    let now = new Date("2026-04-27T00:00:00Z");
    const clock = () => now;
    const s = new InMemoryShareStore({ clock });
    const { share, token } = await s.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 60,
    });
    await s.revokeShare(share.id);
    now = new Date(now.getTime() + 61 * 1000);
    await expect(s.verifyShareToken(token)).rejects.toThrow(ShareRevokedError);
  });

  // ─── revokeShare ───

  it("revokeShare is idempotent — second call returns the original revokedAt", async () => {
    const { share } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const first = await store.revokeShare(share.id);
    const ts = first.revokedAt!;
    const second = await store.revokeShare(share.id);
    expect(second.revokedAt).toEqual(ts);
  });

  it("revokeShare raises ShareNotFoundError for unknown ids", async () => {
    await expect(store.revokeShare(generate("shr") as ShrId)).rejects.toThrow(
      ShareNotFoundError,
    );
  });

  // ─── listSharesForObject ───

  // ─── Spec error precedence: consumed > expired ───

  it("consumed + expired share raises ShareConsumedError (consumed wins)", async () => {
    let now = new Date("2026-04-27T00:00:00Z");
    const clock = () => now;
    const s = new InMemoryShareStore({ clock });
    const { token } = await s.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 60,
      singleUse: true,
    });
    await s.verifyShareToken(token); // consumes
    now = new Date(now.getTime() + 61 * 1000); // now also expired
    await expect(s.verifyShareToken(token)).rejects.toThrow(
      ShareConsumedError,
    );
  });

  // ─── createdBy round-trip ───

  it("createdBy round-trips through getShare", async () => {
    const { share } = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const fetched = await store.getShare(share.id);
    expect(fetched.createdBy).toBe(alice);
    expect(fetched.createdBy).toMatch(/^usr_/);
  });

  // ─── listSharesForObject returns shares in every state ───

  it("listSharesForObject returns active, revoked, and consumed shares", async () => {
    const active = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const revoked = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
    });
    const consumed = await store.createShare({
      objectType: "proj",
      objectId: project42,
      relation: "viewer",
      createdBy: alice,
      expiresInSeconds: 600,
      singleUse: true,
    });
    await store.revokeShare(revoked.share.id);
    await store.verifyShareToken(consumed.token);
    const page = await store.listSharesForObject("proj", project42);
    const ids = new Set(page.data.map((s) => s.id));
    expect(ids.has(active.share.id)).toBe(true);
    expect(ids.has(revoked.share.id)).toBe(true);
    expect(ids.has(consumed.share.id)).toBe(true);
    expect(page.data).toHaveLength(3);
  });

  it("listSharesForObject filters by object and paginates", async () => {
    const objects = [project42, project42, generate("usr").slice(4), project42];
    for (const o of objects) {
      await store.createShare({
        objectType: "proj",
        objectId: o,
        relation: "viewer",
        createdBy: alice,
        expiresInSeconds: 600,
      });
    }
    const all = await store.listSharesForObject("proj", project42);
    expect(all.data.map((s) => s.objectId).every((o) => o === project42)).toBe(true);
    expect(all.data).toHaveLength(3);
    const page1 = await store.listSharesForObject("proj", project42, { limit: 2 });
    expect(page1.data).toHaveLength(2);
    expect(page1.nextCursor).not.toBeNull();
    const page2 = await store.listSharesForObject("proj", project42, {
      limit: 10,
      cursor: page1.nextCursor!,
    });
    const ids = new Set([...page1.data.map((s) => s.id), ...page2.data.map((s) => s.id)]);
    expect(ids.size).toBe(3);
  });
});

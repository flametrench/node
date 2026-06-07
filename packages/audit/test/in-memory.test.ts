// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for InMemoryAuditStore error paths (ADR 0019 error taxonomy,
// spec PR #43). Conformance write/get round-trips are covered by conformance.test.ts.

import { describe, expect, it } from "vitest";

import {
  InMemoryAuditStore,
  InvalidFormatError,
  NotFoundError,
  type WriteAuditInput,
} from "../src/index.js";

const BASE: WriteAuditInput = {
  occurredAt: new Date("2026-06-05T10:00:00.000Z"),
  actorUsrId: null,
  action: "test.action",
  target: { kind: "doc", id: "doc_0190f2a81b3c7abc8123000000000001" },
  outcome: "success",
  metadata: {},
};

describe("InMemoryAuditStore — error taxonomy (ADR 0019 §Errors)", () => {
  describe("outcome validation", () => {
    it("rejects an outcome outside the enum", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({ ...BASE, outcome: "unknown" as never }),
      ).rejects.toThrow(InvalidFormatError);
    });

    it("includes field='outcome' on the error", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({ ...BASE, outcome: "unknown" as never }),
      ).rejects.toMatchObject({ field: "outcome" });
    });
  });

  describe("actor_usr_id validation", () => {
    it("accepts null (pre-auth/system events)", async () => {
      const store = new InMemoryAuditStore();
      await expect(store.write({ ...BASE, actorUsrId: null })).resolves.toBeDefined();
    });

    it("accepts a valid usr_<32hex>", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({ ...BASE, actorUsrId: "usr_0190f2a81b3c7abc8123000000000001" }),
      ).resolves.toBeDefined();
    });

    it("rejects a non-null actor_usr_id that is not a valid usr_<32hex>", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({ ...BASE, actorUsrId: "not-a-usr-id" as never }),
      ).rejects.toThrow(InvalidFormatError);
    });

    it("includes field='actor_usr_id' on the error", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({ ...BASE, actorUsrId: "not-a-usr-id" as never }),
      ).rejects.toMatchObject({ field: "actor_usr_id" });
    });
  });

  describe("target.kind validation", () => {
    it("accepts a Flametrench entity type (usr, org, doc, proj)", async () => {
      const store = new InMemoryAuditStore();
      for (const kind of ["usr", "org", "doc", "proj", "job"]) {
        await expect(
          store.write({ ...BASE, target: { kind, id: "any-id" } }),
        ).resolves.toBeDefined();
      }
    });

    it("rejects a target.kind that doesn't match ^[a-z]{2,6}$", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({ ...BASE, target: { kind: "TooLong-Kind", id: "any" } }),
      ).rejects.toThrow(InvalidFormatError);
    });

    it("rejects a target.kind that is too long", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({ ...BASE, target: { kind: "toolongkind", id: "any" } }),
      ).rejects.toMatchObject({ field: "target.kind" });
    });

    it("rejects a target.kind with uppercase chars", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({ ...BASE, target: { kind: "Doc", id: "any" } }),
      ).rejects.toMatchObject({ field: "target.kind" });
    });
  });

  describe("auth validation — exactly-one-matches constraint", () => {
    it("accepts pat auth with only pat_id", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({
          ...BASE,
          actorUsrId: "usr_0190f2a81b3c7abc8123000000000001",
          auth: { kind: "pat", patId: "pat_0190f2a81b3c7abc8123000000000002" },
        }),
      ).resolves.toBeDefined();
    });

    it("rejects pat auth with session_id instead of pat_id", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({
          ...BASE,
          auth: { kind: "pat", sessionId: "ses_0190f2a81b3c7abc8123000000000003" } as never,
        }),
      ).rejects.toMatchObject({ field: "auth" });
    });

    it("rejects auth with multiple id fields", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({
          ...BASE,
          auth: {
            kind: "session",
            sessionId: "ses_0190f2a81b3c7abc8123000000000003",
            patId: "pat_0190f2a81b3c7abc8123000000000002",
          } as never,
        }),
      ).rejects.toMatchObject({ field: "auth" });
    });

    it("rejects auth with no id field", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({
          ...BASE,
          auth: { kind: "session" } as never,
        }),
      ).rejects.toMatchObject({ field: "auth" });
    });

    it("accepts system auth with system_id (string)", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({
          ...BASE,
          auth: { kind: "system", systemId: "billing-cron" },
        }),
      ).resolves.toBeDefined();
    });
  });

  describe("size validation", () => {
    it("rejects an event whose metadata pushes it over 64 KB", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.write({
          ...BASE,
          metadata: { big: "x".repeat(70 * 1024) },
        }),
      ).rejects.toMatchObject({ field: "size" });
    });
  });

  describe("get — NotFoundError", () => {
    it("throws NotFoundError for an unknown id", async () => {
      const store = new InMemoryAuditStore();
      await expect(
        store.get("aud_0190f2a81b3c7abc8123000000000000" as never),
      ).rejects.toThrow(NotFoundError);
    });

    it("returns the stored event by id", async () => {
      const store = new InMemoryAuditStore();
      const event = await store.write(BASE);
      const fetched = await store.get(event.id);
      expect(fetched.id).toBe(event.id);
      expect(fetched.action).toBe(BASE.action);
    });
  });
});

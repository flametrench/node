// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests: error taxonomy (ADR 0022 §Errors) and lifecycle invariants.

import { describe, expect, it } from "vitest";

import {
  InMemoryNotifyStore,
  InvalidFormatError,
  NotFoundError,
  PreconditionError,
  type CreateNotificationInput,
} from "../src/index.js";

const RECIPIENT: `usr_${string}` = "usr_0190f2a81b3c7abc8123000000000001";
const INTRUDER: `usr_${string}` = "usr_0190f2a81b3c7abc8123000000000099";

const BASE: CreateNotificationInput = {
  scope: "org_0190f2a81b3c7abc8123000000000004",
  recipientUsrId: RECIPIENT,
  type: "comment.mention",
  subject: { kind: "doc", id: "doc_0190f2a81b3c7abc8123000000000002" },
  data: {},
};

function store() {
  return new InMemoryNotifyStore();
}

describe("InMemoryNotifyStore — error taxonomy (ADR 0022 §Errors)", () => {
  describe("scope validation", () => {
    it("rejects invalid scope", async () => {
      await expect(store().createNotification({ ...BASE, scope: "not-an-org" as never }))
        .rejects.toMatchObject({ field: "scope" });
    });
    it("raises InvalidFormatError", async () => {
      await expect(store().createNotification({ ...BASE, scope: "not-an-org" as never }))
        .rejects.toBeInstanceOf(InvalidFormatError);
    });
  });

  describe("recipient_usr_id validation", () => {
    it("rejects invalid recipientUsrId", async () => {
      await expect(store().createNotification({ ...BASE, recipientUsrId: "bad" as never }))
        .rejects.toMatchObject({ field: "recipient_usr_id" });
    });
  });

  describe("type validation", () => {
    it("rejects type outside ^[a-z0-9._-]{1,64}$", async () => {
      await expect(store().createNotification({ ...BASE, type: "CAPS_NOT_OK" }))
        .rejects.toMatchObject({ field: "type" });
    });
    it("rejects empty type", async () => {
      await expect(store().createNotification({ ...BASE, type: "" }))
        .rejects.toMatchObject({ field: "type" });
    });
    it("accepts valid dotted type", async () => {
      await expect(store().createNotification({ ...BASE, type: "invite.received" })).resolves.toBeDefined();
    });
  });

  describe("subject validation", () => {
    it("rejects missing kind", async () => {
      await expect(
        store().createNotification({ ...BASE, subject: { kind: "", id: "x" } }),
      ).rejects.toMatchObject({ field: "subject" });
    });
    it("rejects missing id", async () => {
      await expect(
        store().createNotification({ ...BASE, subject: { kind: "doc", id: "" } }),
      ).rejects.toMatchObject({ field: "subject" });
    });
  });

  describe("data validation", () => {
    it("rejects an array as data", async () => {
      await expect(store().createNotification({ ...BASE, data: [] as never }))
        .rejects.toMatchObject({ field: "data" });
    });
    it("rejects data > 16 KB", async () => {
      await expect(store().createNotification({ ...BASE, data: { x: "a".repeat(20 * 1024) } }))
        .rejects.toMatchObject({ field: "data" });
    });
  });

  describe("PreconditionError — dismissed is terminal", () => {
    it("raises PreconditionError on markRead after dismiss", async () => {
      const s = store();
      const n = await s.createNotification(BASE);
      await s.dismiss(n.id, RECIPIENT);
      await expect(s.markRead(n.id, RECIPIENT)).rejects.toBeInstanceOf(PreconditionError);
    });
    it("raises PreconditionError on markUnread after dismiss", async () => {
      const s = store();
      const n = await s.createNotification(BASE);
      await s.dismiss(n.id, RECIPIENT);
      await expect(s.markUnread(n.id, RECIPIENT)).rejects.toBeInstanceOf(PreconditionError);
    });
    it("raises PreconditionError on dismiss after dismiss", async () => {
      const s = store();
      const n = await s.createNotification(BASE);
      await s.dismiss(n.id, RECIPIENT);
      await expect(s.dismiss(n.id, RECIPIENT)).rejects.toBeInstanceOf(PreconditionError);
    });
  });

  describe("NotFoundError", () => {
    it("raises NotFoundError for unknown id on getNotification", async () => {
      await expect(
        store().getNotification("not_0190f2a81b3c7abc8123000000000000" as never, RECIPIENT),
      ).rejects.toBeInstanceOf(NotFoundError);
    });
    it("raises NotFoundError for unknown id on markRead", async () => {
      await expect(
        store().markRead("not_0190f2a81b3c7abc8123000000000000" as never, RECIPIENT),
      ).rejects.toBeInstanceOf(NotFoundError);
    });
  });
});

describe("InMemoryNotifyStore — recipient-scope non-disclosure (ADR 0022 Option 2)", () => {
  it("cross-recipient getNotification raises NotFoundError", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    await expect(s.getNotification(n.id, INTRUDER)).rejects.toBeInstanceOf(NotFoundError);
  });

  it("cross-recipient and nonexistent raise the same NotFoundError (indistinguishable)", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    const foreignErr = await s.getNotification(n.id, INTRUDER).catch((e) => e);
    const missingErr = await s.getNotification("not_0190f2a81b3c7abc8123000000000000" as never, INTRUDER).catch((e) => e);
    expect(foreignErr).toBeInstanceOf(NotFoundError);
    expect(missingErr).toBeInstanceOf(NotFoundError);
    expect(foreignErr.code).toBe(missingErr.code);
  });

  it("dismiss by intruder on foreign already-dismissed raises NotFoundError, not PreconditionError (ownership before state)", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    await s.dismiss(n.id, RECIPIENT);
    // If state were checked first, this would raise PreconditionError — ownership must win.
    await expect(s.dismiss(n.id, INTRUDER)).rejects.toBeInstanceOf(NotFoundError);
  });

  it("markRead by intruder raises NotFoundError", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    await expect(s.markRead(n.id, INTRUDER)).rejects.toBeInstanceOf(NotFoundError);
  });

  it("markUnread by intruder raises NotFoundError", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    await expect(s.markUnread(n.id, INTRUDER)).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe("InMemoryNotifyStore — lifecycle invariants", () => {
  it("creates notification as unread", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    expect(n.state).toBe("unread");
  });

  it("markRead transitions to read", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    const r = await s.markRead(n.id, RECIPIENT);
    expect(r.state).toBe("read");
  });

  it("markUnread toggles back to unread", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    await s.markRead(n.id, RECIPIENT);
    const r = await s.markUnread(n.id, RECIPIENT);
    expect(r.state).toBe("unread");
  });

  it("dismiss from unread reaches dismissed", async () => {
    const s = store();
    const n = await s.createNotification(BASE);
    const r = await s.dismiss(n.id, RECIPIENT);
    expect(r.state).toBe("dismissed");
  });

  it("data is stored verbatim", async () => {
    const s = store();
    const data = { actor_name: "Alice", count: 42, nested: { x: true } };
    const n = await s.createNotification({ ...BASE, data });
    expect(n.data).toEqual(data);
  });

  it("countUnread returns correct count", async () => {
    const s = store();
    const scope = BASE.scope;
    await s.createNotification(BASE);
    await s.createNotification(BASE);
    const n3 = await s.createNotification(BASE);
    await s.markRead(n3.id, RECIPIENT);
    expect(await s.countUnread(RECIPIENT, scope)).toBe(2);
  });

  it("countUnread is scoped to recipient and org", async () => {
    const s = store();
    await s.createNotification(BASE);
    // Different recipient — should not count
    await s.createNotification({ ...BASE, recipientUsrId: INTRUDER });
    expect(await s.countUnread(RECIPIENT, BASE.scope)).toBe(1);
    expect(await s.countUnread(INTRUDER, BASE.scope)).toBe(1);
  });
});

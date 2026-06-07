// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests: error taxonomy, lifecycle invariants, and evaluate logic.

import { describe, expect, it } from "vitest";

import {
  InMemoryFlagStore,
  InvalidFormatError,
  NotFoundError,
  PreconditionError,
  type CreateFlagInput,
} from "../src/index.js";

const BASE: CreateFlagInput = {
  scope: "org_0190f2a81b3c7abc8123000000000004",
  key: "new-checkout",
  enabled: true,
  default_variant: false,
  rules: [],
};

function store() {
  return new InMemoryFlagStore();
}

describe("InMemoryFlagStore — error taxonomy", () => {
  describe("scope validation", () => {
    it("rejects invalid scope", async () => {
      await expect(store().createFlag({ ...BASE, scope: "not-an-org" as never }))
        .rejects.toMatchObject({ field: "scope" });
    });
    it("raises InvalidFormatError", async () => {
      await expect(store().createFlag({ ...BASE, scope: "not-an-org" as never }))
        .rejects.toBeInstanceOf(InvalidFormatError);
    });
  });

  describe("key validation", () => {
    it("rejects key with uppercase", async () => {
      await expect(store().createFlag({ ...BASE, key: "Bad_Key" }))
        .rejects.toMatchObject({ field: "key" });
    });
    it("rejects empty key", async () => {
      await expect(store().createFlag({ ...BASE, key: "" }))
        .rejects.toMatchObject({ field: "key" });
    });
    it("rejects key > 128 chars", async () => {
      await expect(store().createFlag({ ...BASE, key: "a".repeat(129) }))
        .rejects.toMatchObject({ field: "key" });
    });
    it("accepts valid dotted key", async () => {
      await expect(store().createFlag({ ...BASE, key: "feature.dark-mode" })).resolves.toBeDefined();
    });
  });

  describe("rules validation", () => {
    it("rejects non-array rules", async () => {
      await expect(store().createFlag({ ...BASE, rules: "bad" as never }))
        .rejects.toMatchObject({ field: "rules" });
    });
    it("rejects authz rule with bad relation", async () => {
      await expect(
        store().createFlag({
          ...BASE,
          rules: [{ kind: "authz", relation: "BAD_RELATION", object: { type: "org", id: "org_x" }, variant: true }],
        }),
      ).rejects.toMatchObject({ field: "rules" });
    });
    it("rejects percentage rule with basis_points > 10000", async () => {
      await expect(
        store().createFlag({
          ...BASE,
          rules: [{ kind: "percentage", basis_points: 10001, variant: true }],
        }),
      ).rejects.toMatchObject({ field: "rules" });
    });
    it("rejects percentage rule with negative basis_points", async () => {
      await expect(
        store().createFlag({
          ...BASE,
          rules: [{ kind: "percentage", basis_points: -1, variant: true }],
        }),
      ).rejects.toMatchObject({ field: "rules" });
    });
    it("accepts valid authz rule", async () => {
      await expect(
        store().createFlag({
          ...BASE,
          rules: [{ kind: "authz", relation: "editor", object: { type: "org", id: "org_0190f2a81b3c7abc8123000000000004" }, variant: true }],
        }),
      ).resolves.toBeDefined();
    });
    it("accepts valid percentage rule at boundary (10000)", async () => {
      await expect(
        store().createFlag({ ...BASE, rules: [{ kind: "percentage", basis_points: 10000, variant: true }] }),
      ).resolves.toBeDefined();
    });
  });

  describe("PreconditionError — duplicate key within scope", () => {
    it("raises PreconditionError on duplicate key in same scope", async () => {
      const s = store();
      await s.createFlag(BASE);
      await expect(s.createFlag(BASE)).rejects.toBeInstanceOf(PreconditionError);
    });
    it("allows same key in different scope", async () => {
      const s = store();
      await s.createFlag(BASE);
      await expect(
        s.createFlag({ ...BASE, scope: "org_0190f2a81b3c7abc8123000000000099" as never }),
      ).resolves.toBeDefined();
    });
  });

  describe("NotFoundError", () => {
    it("raises NotFoundError for unknown id on getFlag", async () => {
      await expect(
        store().getFlag("flag_0190f2a81b3c7abc8123000000000000" as never),
      ).rejects.toBeInstanceOf(NotFoundError);
    });
    it("raises NotFoundError for unknown key on getFlagByKey", async () => {
      await expect(
        store().getFlagByKey("org_0190f2a81b3c7abc8123000000000004", "nonexistent"),
      ).rejects.toBeInstanceOf(NotFoundError);
    });
    it("raises NotFoundError for unknown id on updateFlag", async () => {
      await expect(
        store().updateFlag("flag_0190f2a81b3c7abc8123000000000000" as never, { enabled: false }),
      ).rejects.toBeInstanceOf(NotFoundError);
    });
  });
});

describe("InMemoryFlagStore — lifecycle invariants", () => {
  it("creates flag with correct shape", async () => {
    const s = store();
    const f = await s.createFlag(BASE);
    expect(f.scope).toBe(BASE.scope);
    expect(f.key).toBe(BASE.key);
    expect(f.enabled).toBe(true);
    expect(f.default_variant).toBe(false);
    expect(f.rules).toHaveLength(0);
    expect(f.id).toMatch(/^flag_/);
  });

  it("updateFlag mutates enabled and default_variant", async () => {
    const s = store();
    const f = await s.createFlag(BASE);
    const u = await s.updateFlag(f.id, { enabled: false, default_variant: true });
    expect(u.enabled).toBe(false);
    expect(u.default_variant).toBe(true);
  });

  it("updateFlag does not mutate key or scope", async () => {
    const s = store();
    const f = await s.createFlag(BASE);
    const u = await s.updateFlag(f.id, { enabled: false });
    expect(u.key).toBe(BASE.key);
    expect(u.scope).toBe(BASE.scope);
  });

  it("deleteFlag removes flag from store", async () => {
    const s = store();
    const f = await s.createFlag(BASE);
    await s.deleteFlag(f.id);
    await expect(s.getFlag(f.id)).rejects.toBeInstanceOf(NotFoundError);
  });

  it("deleteFlag removes key from index (allows re-create)", async () => {
    const s = store();
    const f = await s.createFlag(BASE);
    await s.deleteFlag(f.id);
    await expect(s.createFlag(BASE)).resolves.toBeDefined();
  });
});

describe("InMemoryFlagStore — evaluate", () => {
  it("returns false for unknown flag (safe default)", async () => {
    const s = store();
    const result = await s.evaluate("org_0190f2a81b3c7abc8123000000000004", "unknown-flag", "usr_x");
    expect(result).toBe(false);
  });

  it("returns default_variant when enabled is false", async () => {
    const s = store();
    const f = await s.createFlag({ ...BASE, enabled: false, default_variant: true });
    const result = await s.evaluate(f.scope, f.key, "usr_0190f2a81b3c7abc8123000000000002");
    expect(result).toBe(true);
  });

  it("returns default_variant when no rules match", async () => {
    const s = store();
    const f = await s.createFlag({ ...BASE, enabled: true, default_variant: false, rules: [] });
    const result = await s.evaluate(f.scope, f.key, "usr_0190f2a81b3c7abc8123000000000002");
    expect(result).toBe(false);
  });

  it("percentage rule: 10000 basis_points matches all subjects", async () => {
    const s = store();
    const f = await s.createFlag({
      ...BASE,
      rules: [{ kind: "percentage", basis_points: 10000, variant: true }],
    });
    const result = await s.evaluate(f.scope, f.key, "usr_0190f2a81b3c7abc8123000000000002");
    expect(result).toBe(true);
  });

  it("percentage rule: 0 basis_points matches no subjects", async () => {
    const s = store();
    const f = await s.createFlag({
      ...BASE,
      rules: [{ kind: "percentage", basis_points: 0, variant: true }],
    });
    const result = await s.evaluate(f.scope, f.key, "usr_0190f2a81b3c7abc8123000000000002");
    expect(result).toBe(false);
  });

  it("authz rule: matching check() returns rule variant", async () => {
    const checkFn = async () => true;
    const s = new InMemoryFlagStore(checkFn);
    const f = await s.createFlag({
      ...BASE,
      rules: [{ kind: "authz", relation: "editor", object: { type: "org", id: BASE.scope }, variant: true }],
    });
    const result = await s.evaluate(f.scope, f.key, "usr_0190f2a81b3c7abc8123000000000002");
    expect(result).toBe(true);
  });

  it("authz rule: non-matching check() falls through to default_variant", async () => {
    const checkFn = async () => false;
    const s = new InMemoryFlagStore(checkFn);
    const f = await s.createFlag({
      ...BASE,
      default_variant: false,
      rules: [{ kind: "authz", relation: "editor", object: { type: "org", id: BASE.scope }, variant: true }],
    });
    const result = await s.evaluate(f.scope, f.key, "usr_0190f2a81b3c7abc8123000000000002");
    expect(result).toBe(false);
  });

  it("first matching rule wins (ordered evaluation)", async () => {
    const s = store();
    const f = await s.createFlag({
      ...BASE,
      rules: [
        { kind: "percentage", basis_points: 10000, variant: true },
        { kind: "percentage", basis_points: 10000, variant: false },
      ],
    });
    const result = await s.evaluate(f.scope, f.key, "usr_0190f2a81b3c7abc8123000000000002");
    expect(result).toBe(true);
  });
});

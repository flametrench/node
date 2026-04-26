// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Unit tests for v0.2 rewrite-rule evaluation in the Node SDK.
// Mirrors authz-python/tests/test_rewrite_rules.py exactly so any
// behavioral drift between the two implementations surfaces as a
// failing test.

import { generate } from "@flametrench/ids";
import { beforeEach, describe, expect, it } from "vitest";

import {
  EvaluationLimitExceededError,
  InMemoryTupleStore,
  type Rules,
  type UsrId,
} from "../src/index.js";

let alice: UsrId;
let proj42: string;
let orgAcme: string;

beforeEach(() => {
  alice = generate("usr") as UsrId;
  proj42 = generate("org").slice(4);
  orgAcme = generate("org").slice(4);
});

describe("empty rules → v0.1-equivalent", () => {
  it("no rules means no derivation", async () => {
    const store = new InMemoryTupleStore(); // rules undefined
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: proj42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(false);
  });

  it("empty rules object means no derivation", async () => {
    const store = new InMemoryTupleStore({ rules: {} });
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: proj42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(false);
  });
});

describe("computed_userset (role implication)", () => {
  it("editor implies viewer", async () => {
    const rules: Rules = {
      proj: {
        viewer: [
          { type: "this" },
          { type: "computed_userset", relation: "editor" },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules });
    const editorTup = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "editor",
      objectType: "proj",
      objectId: proj42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(true);
    expect(result.matchedTupleId).toBe(editorTup.id);
  });

  it("admin → editor → viewer chain", async () => {
    const rules: Rules = {
      proj: {
        viewer: [
          { type: "this" },
          { type: "computed_userset", relation: "editor" },
        ],
        editor: [
          { type: "this" },
          { type: "computed_userset", relation: "admin" },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules });
    const adminTup = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "admin",
      objectType: "proj",
      objectId: proj42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(true);
    expect(result.matchedTupleId).toBe(adminTup.id);
  });

  it("missing intermediate rule breaks the chain", async () => {
    const rules: Rules = {
      proj: {
        viewer: [
          { type: "this" },
          { type: "computed_userset", relation: "editor" },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules });
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "admin",
      objectType: "proj",
      objectId: proj42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(false);
  });
});

describe("tuple_to_userset (parent-child inheritance)", () => {
  it("org admin implies proj admin via parent_org", async () => {
    const rules: Rules = {
      proj: {
        admin: [
          { type: "this" },
          {
            type: "tuple_to_userset",
            tuplesetRelation: "parent_org",
            computedUsersetRelation: "admin",
          },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules });
    const orgAdminTup = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "admin",
      objectType: "org",
      objectId: orgAcme,
    });
    await store.createTuple({
      subjectType: "org" as never,
      subjectId: orgAcme as UsrId,
      relation: "parent_org",
      objectType: "proj",
      objectId: proj42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "admin",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(true);
    expect(result.matchedTupleId).toBe(orgAdminTup.id);
  });

  it("org member does not imply proj admin", async () => {
    const rules: Rules = {
      proj: {
        admin: [
          { type: "this" },
          {
            type: "tuple_to_userset",
            tuplesetRelation: "parent_org",
            computedUsersetRelation: "admin",
          },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules });
    await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "member",
      objectType: "org",
      objectId: orgAcme,
    });
    await store.createTuple({
      subjectType: "org" as never,
      subjectId: orgAcme as UsrId,
      relation: "parent_org",
      objectType: "proj",
      objectId: proj42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "admin",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(false);
  });
});

describe("cycle detection", () => {
  it("self-referential cycle terminates silently", async () => {
    const rules: Rules = {
      proj: {
        viewer: [
          { type: "this" },
          { type: "computed_userset", relation: "viewer" },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(false);
  });

  it("two-node cycle terminates silently", async () => {
    const rules: Rules = {
      proj: {
        viewer: [
          { type: "this" },
          { type: "computed_userset", relation: "editor" },
        ],
        editor: [
          { type: "this" },
          { type: "computed_userset", relation: "viewer" },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(false);
  });
});

describe("evaluation limits", () => {
  it("depth limit raises", async () => {
    const rules: Rules = {
      proj: {
        r0: [{ type: "this" }, { type: "computed_userset", relation: "r1" }],
        r1: [{ type: "this" }, { type: "computed_userset", relation: "r2" }],
        r2: [{ type: "this" }, { type: "computed_userset", relation: "r3" }],
        r3: [{ type: "this" }, { type: "computed_userset", relation: "r4" }],
      },
    };
    const store = new InMemoryTupleStore({ rules, maxDepth: 2 });
    await expect(
      store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "r0",
        objectType: "proj",
        objectId: proj42,
      }),
    ).rejects.toThrow(EvaluationLimitExceededError);
  });

  it("fan-out limit raises", async () => {
    const rules: Rules = {
      proj: {
        admin: [
          { type: "this" },
          {
            type: "tuple_to_userset",
            tuplesetRelation: "parent_org",
            computedUsersetRelation: "admin",
          },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules, maxFanOut: 3 });
    for (let i = 0; i < 5; i++) {
      await store.createTuple({
        subjectType: "org" as never,
        subjectId: generate("org").slice(4) as UsrId,
        relation: "parent_org",
        objectType: "proj",
        objectId: proj42,
      });
    }
    await expect(
      store.check({
        subjectType: "usr",
        subjectId: alice,
        relation: "admin",
        objectType: "proj",
        objectId: proj42,
      }),
    ).rejects.toThrow(EvaluationLimitExceededError);
  });
});

describe("direct fast path bypasses rules", () => {
  it("a direct match short-circuits an otherwise-cycling rule set", async () => {
    const rules: Rules = {
      proj: {
        viewer: [
          { type: "this" },
          { type: "computed_userset", relation: "viewer" },
        ],
      },
    };
    const store = new InMemoryTupleStore({ rules, maxDepth: 2 });
    const direct = await store.createTuple({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    const result = await store.check({
      subjectType: "usr",
      subjectId: alice,
      relation: "viewer",
      objectType: "proj",
      objectId: proj42,
    });
    expect(result.allowed).toBe(true);
    expect(result.matchedTupleId).toBe(direct.id);
  });
});

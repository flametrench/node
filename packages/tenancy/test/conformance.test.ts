// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.1 conformance suite — Node / TypeScript harness for
// the tenancy capability.
//
// Implements the state-machine fixture format defined in
// spec/conformance/fixture.schema.json. Each test:
//
//   1. Pre-allocates fresh usr_ IDs for declared named users.
//   2. Creates a fresh InMemoryTenancyStore.
//   3. Walks the steps list. Each step's input has {name} references
//      resolved against the variable map (declared users + previous
//      captures). The step calls the matching operation; on success
//      captures may extract values for later substitution; on
//      expected error the step MUST throw.
//
// Pseudo-ops recognized only by the harness (not part of the SDK
// surface):
//
//   - assert_subject_relations(subject_type, subject_id, relations[])
//   - assert_equal(actual, expected)
//
// The Python harness in flametrench-tenancy is the canonical reference
// implementation; this Node harness mirrors it with snake_case →
// camelCase adaptation on inputs and capture paths.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { generate } from "@flametrench/ids";
import { describe, expect, it } from "vitest";

import {
  AlreadyTerminalError,
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
  type MemId,
  type OrgId,
  type Role,
  type UsrId,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "conformance/fixtures");

const VAR_PATTERN = /^\{([a-z_][a-z0-9_]*)\}$/;

const ERROR_CLASSES = {
  SoleOwnerError,
  RoleHierarchyError,
  ForbiddenError,
  DuplicateMembershipError,
  InvitationNotPendingError,
  InvitationExpiredError,
  PreconditionError,
  AlreadyTerminalError,
  NotFoundError,
  IdentifierBindingRequiredError,
  IdentifierMismatchError,
} as const;

interface FixtureFile {
  spec_version: string;
  capability: string;
  operation: string;
  conformance_level: "MUST" | "SHOULD" | "MAY";
  description: string;
  tests: FixtureTest[];
}

interface FixtureTest {
  id: string;
  description: string;
  users?: string[];
  steps: Step[];
}

interface Step {
  op: string;
  input: Record<string, unknown>;
  captures?: Record<string, string>;
  expected?: { error?: string; result?: unknown };
}

function loadFixture(relativePath: string): FixtureFile {
  return JSON.parse(readFileSync(join(FIXTURES_DIR, relativePath), "utf8"));
}

/** Recursively substitute {var} references in a value tree. */
function resolveVars(value: unknown, variables: Record<string, unknown>): unknown {
  if (typeof value === "string") {
    const match = VAR_PATTERN.exec(value);
    if (match) {
      const name = match[1]!;
      if (!(name in variables)) {
        throw new Error(`Unknown variable in fixture: {${name}}`);
      }
      return variables[name];
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => resolveVars(v, variables));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = resolveVars(v, variables);
    }
    return out;
  }
  return value;
}

/** snake_case → camelCase. */
function toCamel(segment: string): string {
  return segment.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

/**
 * Walk a dotted path into a value. Tries snake_case as-is first, then
 * camelCase, so fixture paths like `owner_membership.id` resolve
 * against the JS field name `ownerMembership`.
 */
function walkPath(obj: unknown, dottedPath: string): unknown {
  let current = obj;
  for (const segment of dottedPath.split(".")) {
    const camel = toCamel(segment);
    if (current !== null && typeof current === "object") {
      const rec = current as Record<string, unknown>;
      if (segment in rec) current = rec[segment];
      else if (camel in rec) current = rec[camel];
      else throw new Error(`Cannot resolve path segment '${segment}'`);
    } else {
      throw new Error(`Cannot walk into non-object at '${segment}'`);
    }
  }
  return current;
}

/** Convert all snake_case keys in a flat input record to camelCase. */
function camelizeKeys(args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    out[toCamel(k)] = v;
  }
  return out;
}

interface PreTupleArg {
  relation: string;
  object_type: string;
  object_id: string;
}

function buildPreTuples(values?: PreTupleArg[]): unknown {
  if (!values) return [];
  return values.map((v) => ({
    relation: v.relation,
    objectType: v.object_type,
    objectId: v.object_id,
  }));
}

/** Dispatch a fixture op to the matching SDK or harness method. */
async function invokeOp(
  store: InMemoryTenancyStore,
  op: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  switch (op) {
    case "create_org":
      return store.createOrg(args.creator as UsrId);

    case "add_member":
      return store.addMember({
        orgId: args.org_id as OrgId,
        usrId: args.usr_id as UsrId,
        role: args.role as Role,
        invitedBy: (args.invited_by ?? null) as UsrId | null,
      });

    case "change_role":
      return store.changeRole({
        memId: args.mem_id as MemId,
        newRole: args.new_role as Role,
      });

    case "suspend_membership":
      return store.suspendMembership(args.mem_id as MemId);

    case "reinstate_membership":
      return store.reinstateMembership(args.mem_id as MemId);

    case "self_leave":
      return store.selfLeave({
        memId: args.mem_id as MemId,
        transferTo: args.transfer_to as UsrId | undefined,
      });

    case "admin_remove":
      return store.adminRemove({
        memId: args.mem_id as MemId,
        adminUsrId: args.admin_usr_id as UsrId,
      });

    case "transfer_ownership":
      return store.transferOwnership({
        orgId: args.org_id as OrgId,
        fromMemId: args.from_mem_id as MemId,
        toMemId: args.to_mem_id as MemId,
      });

    case "create_invitation": {
      const ttl = (args.ttl_seconds as number | undefined) ?? 86400;
      return store.createInvitation({
        orgId: args.org_id as OrgId,
        identifier: args.identifier as string,
        role: args.role as Role,
        invitedBy: args.invited_by as UsrId,
        expiresAt: new Date(Date.now() + ttl * 1000),
        preTuples: buildPreTuples(args.pre_tuples as PreTupleArg[] | undefined) as never,
      });
    }

    case "accept_invitation":
      return store.acceptInvitation({
        invId: args.inv_id as `inv_${string}`,
        asUsrId: args.as_usr_id as UsrId | undefined,
        acceptingIdentifier: args.accepting_identifier as string | undefined,
      });

    case "decline_invitation":
      return store.declineInvitation({
        invId: args.inv_id as `inv_${string}`,
        asUsrId: (args.as_usr_id ?? null) as UsrId | null,
      });

    case "revoke_invitation":
      return store.revokeInvitation({
        invId: args.inv_id as `inv_${string}`,
        adminUsrId: args.admin_usr_id as UsrId,
      });

    case "suspend_org":
      return store.suspendOrg(args.org_id as OrgId);
    case "reinstate_org":
      return store.reinstateOrg(args.org_id as OrgId);
    case "revoke_org":
      return store.revokeOrg(args.org_id as OrgId);

    // Harness-only assertion pseudo-ops.
    case "assert_subject_relations": {
      const tuples = await store.listTuplesForSubject(
        "usr",
        args.subject_id as UsrId,
      );
      const actual = tuples.map((t) => t.relation).sort();
      const expectedRelations = (args.relations as string[]).slice().sort();
      expect(actual).toEqual(expectedRelations);
      return null;
    }

    case "assert_equal":
      expect(args.actual).toBe(args.expected);
      return null;

    case "assert_invitation_status": {
      const inv = await store.getInvitation(args.inv_id as `inv_${string}`);
      expect(inv.status).toBe(args.expected_status);
      return null;
    }

    default:
      throw new Error(`Unknown fixture op: ${op}`);
  }
}

async function runTest(test: FixtureTest): Promise<void> {
  const store = new InMemoryTenancyStore();
  const variables: Record<string, unknown> = {};
  for (const name of test.users ?? []) {
    variables[name] = generate("usr");
  }

  for (const step of test.steps) {
    const resolvedInput = resolveVars(step.input, variables) as Record<
      string,
      unknown
    >;

    if (step.expected?.error) {
      const errorName = step.expected.error;
      const Ctor = (ERROR_CLASSES as Record<string, unknown>)[errorName];
      if (!Ctor) throw new Error(`Unknown spec error: ${errorName}`);
      await expect(invokeOp(store, step.op, resolvedInput)).rejects.toThrow(
        Ctor as never,
      );
      return;
    }

    const result = await invokeOp(store, step.op, resolvedInput);

    if (step.captures) {
      for (const [name, path] of Object.entries(step.captures)) {
        variables[name] = walkPath(result, path);
      }
    }
  }

  // "Completed without error" sentinel for tests that do mutations only.
  expect(true).toBe(true);
}

// ─── Test factories ───

for (const [name, file] of [
  ["tenancy.self_leave", "tenancy/self-leave.json"],
  ["tenancy.change_role", "tenancy/change-role.json"],
  ["tenancy.transfer_ownership", "tenancy/transfer-ownership.json"],
  ["tenancy.admin_remove", "tenancy/admin-remove.json"],
  ["tenancy.accept_invitation", "tenancy/invitation-accept.json"],
  ["tenancy.accept_invitation.binding", "tenancy/invitation-accept-binding.json"],
] as const) {
  const fixture = loadFixture(file);
  describe(`Conformance · ${name} [${fixture.conformance_level}]`, () => {
    for (const t of fixture.tests) {
      it(`[${t.id}] ${t.description}`, async () => {
        await runTest(t);
      });
    }
  });
}

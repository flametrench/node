# @flametrench/tenancy

Tenancy primitives for [Flametrench](https://flametrench.dev): organizations, memberships, and invitations. Spec-conformant revoke-and-re-add lifecycle, atomic invitation acceptance, sole-owner protection, and an `mem_`/`tup_` duality that cannot drift.

**Status:** v0.0.1 — early draft. API subject to change before the v0.1.0 release alongside `@flametrench/ids@0.1.0`. The in-memory store is reference / test infrastructure; a Postgres-backed store is planned for a future release.

## Install

```bash
pnpm add @flametrench/tenancy
```

## Quick start

```ts
import { InMemoryTenancyStore } from "@flametrench/tenancy";
import { generate } from "@flametrench/ids";

const store = new InMemoryTenancyStore();

const alice = generate("usr") as `usr_${string}`;
const bob = generate("usr") as `usr_${string}`;

// Alice creates Acme Corp and becomes its owner.
const { org, ownerMembership } = await store.createOrg(alice);

// Alice invites Bob as a member.
const invitation = await store.createInvitation({
  orgId: org.id,
  identifier: "bob@acme.example",
  role: "member",
  invitedBy: alice,
  expiresAt: new Date(Date.now() + 7 * 24 * 3600_000),
});

// Bob accepts. Membership row is created and the authorization tuple is
// materialized atomically.
const { membership, materializedTuples } = await store.acceptInvitation({
  invId: invitation.id,
  asUsrId: bob,
});

// Bob gets promoted to admin. Revoke + re-add: the old mem is marked
// revoked with the new mem's `replaces` pointing at it.
const promoted = await store.changeRole({
  memId: membership.id,
  newRole: "admin",
});
console.log(promoted.replaces === membership.id); // true
```

## API shape

Every backend implements the same `TenancyStore` interface:

```ts
interface TenancyStore {
  // Organizations
  createOrg(creator: UsrId): Promise<{ org: Organization; ownerMembership: Membership }>;
  getOrg(orgId: OrgId): Promise<Organization>;
  suspendOrg / reinstateOrg / revokeOrg(orgId: OrgId): Promise<Organization>;

  // Memberships
  addMember(input: AddMemberInput): Promise<Membership>;
  getMembership(memId: MemId): Promise<Membership>;
  listMembers(orgId: OrgId, options?): Promise<Page<Membership>>;
  changeRole(input: ChangeRoleInput): Promise<Membership>;
  suspendMembership / reinstateMembership(memId: MemId): Promise<Membership>;
  selfLeave(input: SelfLeaveInput): Promise<Membership>;
  adminRemove(input: AdminRemoveInput): Promise<Membership>;
  transferOwnership(input): Promise<{ fromMembership; toMembership }>;

  // Invitations
  createInvitation(input): Promise<Invitation>;
  getInvitation(invId): Promise<Invitation>;
  listInvitations(orgId, options?): Promise<Page<Invitation>>;
  acceptInvitation(input): Promise<AcceptInvitationResult>;
  declineInvitation(input): Promise<Invitation>;
  revokeInvitation(input): Promise<Invitation>;

  // Authorization tuple accessors (read-only)
  listTuplesForSubject(subjectType, subjectId): Promise<Tuple[]>;
  listTuplesForObject(objectType, objectId, relation?): Promise<Tuple[]>;
}
```

## Spec conformance

This package implements the tenancy layer of Flametrench v0.1. See the normative specification at [`spec/docs/tenancy.md`](https://github.com/flametrench/spec/blob/main/docs/tenancy.md) and the design decisions at [ADR 0002](https://github.com/flametrench/spec/blob/main/decisions/0002-tenancy-model.md) and [ADR 0003](https://github.com/flametrench/spec/blob/main/decisions/0003-invitation-state-machine.md).

Conformance fixtures for tenancy are staged in [`spec/conformance/fixtures/tenancy/`](https://github.com/flametrench/spec/blob/main/conformance/fixtures/tenancy/README.md); the fixture harness lands alongside the Postgres-backed store.

### Behaviors that are NOT yet spec-fixture-verified

Until the tenancy fixtures land (they require a stateful harness), the behaviors below are validated only by this package's internal unit tests. The unit tests match the spec exactly; the fixture-level verification adds cross-SDK byte-identity guarantees:

- Atomic accept-invitation transaction (user creation if needed, `mem_` insert, membership `tup_` insert, `pre_tuples` expansion, invitation state transition — all in one logical transaction).
- `mem_` / `tup_` duality under every lifecycle transition.
- Sole-owner protection on self-leave, admin-remove, suspend, and role-change.
- `removed_by` attribution (null ⇒ self-initiated, non-null ⇒ admin-initiated).
- Ownership transfer atomicity.

## Errors

Every error is an instance of `TenancyError` with a stable machine-readable `code`:

| Class | Code | When |
|---|---|---|
| `NotFoundError` | `not_found` | Referenced entity does not exist. |
| `SoleOwnerError` | `conflict.sole_owner` | Operation would leave the org ownerless. |
| `RoleHierarchyError` | `forbidden.role_hierarchy` | Admin rank insufficient for target. |
| `DuplicateMembershipError` | `conflict.duplicate_membership` | User already has an active membership in this org. |
| `AlreadyTerminalError` | `conflict.already_terminal` | Entity is already in a terminal state. |
| `InvitationExpiredError` | `conflict.invitation_expired` | Invitation's TTL has elapsed. |
| `InvitationNotPendingError` | `conflict.invitation_not_pending` | Invitation is already in a terminal state. |
| `ForbiddenError` | `forbidden` | Caller is not authorized. |
| `PreconditionError` | `precondition.<specific>` | A specific precondition was not met. |

## Development

```bash
pnpm install
pnpm -r build       # builds @flametrench/ids first, then @flametrench/tenancy
pnpm -r test        # 60 ids tests + 43 tenancy tests
pnpm -r typecheck
```

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// revokeInvitation authorization: a refused call leaves the invitation
// untouched. Runs against InMemoryTenancyStore and, when TENANCY_POSTGRES_URL
// is set, PostgresTenancyStore.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decode, generate } from "@flametrench/ids";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  ForbiddenError,
  InMemoryTenancyStore,
  type TenancyStore,
  type UsrId,
} from "../src/index.js";
import { PostgresTenancyStore } from "../src/postgres.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SQL = readFileSync(join(__dirname, "postgres-schema.sql"), "utf8");
const POSTGRES_URL = process.env.TENANCY_POSTGRES_URL;

interface Env {
  store: TenancyStore;
  newUser(): Promise<UsrId>;
}

function suite(name: string, makeEnv: () => Promise<Env>): void {
  describe(`${name}: revokeInvitation authorization`, () => {
    async function setup() {
      const env = await makeEnv();
      const owner = await env.newUser();
      const other = await env.newUser();
      const { org } = await env.store.createOrg({ creator: owner });
      const inv = await env.store.createInvitation({
        orgId: org.id,
        identifier: "invitee@example.com",
        role: "member",
        invitedBy: owner,
        expiresAt: new Date(Date.now() + 86_400_000),
      });
      return { ...env, owner, other, org, inv };
    }

    it("a refused plain member leaves the invitation pending and still revocable", async () => {
      const { store, owner, other, org, inv } = await setup();
      await store.addMember({ orgId: org.id, usrId: other, role: "member" });

      await expect(
        store.revokeInvitation({ invId: inv.id, adminUsrId: other }),
      ).rejects.toBeInstanceOf(ForbiddenError);

      const after = await store.getInvitation(inv.id);
      expect(after.status).toBe("pending");
      expect(after.terminalAt).toBeNull();
      expect(after.terminalBy).toBeNull();

      const revoked = await store.revokeInvitation({ invId: inv.id, adminUsrId: owner });
      expect(revoked.status).toBe("revoked");
      expect(revoked.terminalBy).toBe(owner);
    });

    it("a refused non-member leaves the invitation pending", async () => {
      const { store, other, inv } = await setup();
      await expect(
        store.revokeInvitation({ invId: inv.id, adminUsrId: other }),
      ).rejects.toBeInstanceOf(ForbiddenError);
      expect((await store.getInvitation(inv.id)).status).toBe("pending");
    });

    it("a refused suspended admin leaves the invitation pending", async () => {
      const { store, other, org, inv } = await setup();
      const mem = await store.addMember({ orgId: org.id, usrId: other, role: "admin" });
      await store.suspendMembership(mem.id);
      await expect(
        store.revokeInvitation({ invId: inv.id, adminUsrId: other }),
      ).rejects.toBeInstanceOf(ForbiddenError);
      expect((await store.getInvitation(inv.id)).status).toBe("pending");
    });

    it("authorization is checked before status, so a non-admin learns nothing", async () => {
      const { store, owner, other, inv } = await setup();
      await store.revokeInvitation({ invId: inv.id, adminUsrId: owner });
      await expect(
        store.revokeInvitation({ invId: inv.id, adminUsrId: other }),
      ).rejects.toBeInstanceOf(ForbiddenError);
    });
  });
}

suite("in-memory", async () => ({
  store: new InMemoryTenancyStore(),
  newUser: async () => generate("usr") as UsrId,
}));

describe.skipIf(!POSTGRES_URL)("postgres", () => {
  let pool: Pool;
  beforeAll(() => {
    pool = new Pool({ connectionString: POSTGRES_URL });
  });
  afterAll(async () => {
    await pool.end();
  });
  suite("postgres", async () => {
    await pool.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
    await pool.query(SCHEMA_SQL);
    return {
      store: new PostgresTenancyStore(pool),
      newUser: async () => {
        const id = generate("usr") as UsrId;
        await pool.query(`INSERT INTO usr (id, status) VALUES ($1, 'active')`, [decode(id).uuid]);
        return id;
      },
    };
  });
});

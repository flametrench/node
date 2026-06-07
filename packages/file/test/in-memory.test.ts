// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests: error taxonomy, lifecycle invariants, and soft-delete behavior.

import { describe, expect, it } from "vitest";

import {
  InMemoryFileMetadataStore,
  InvalidFormatError,
  NotFoundError,
  PreconditionError,
  type CreateFileMetadataInput,
} from "../src/index.js";

const VALID_CHECKSUM = {
  algo: "sha-256" as const,
  value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
};

const BASE_ACTIVE: CreateFileMetadataInput = {
  scope: "org_0190f2a81b3c7abc8123000000000004",
  ownerUsrId: "usr_0190f2a81b3c7abc8123000000000001",
  name: "report.pdf",
  contentType: "application/pdf",
  sizeBytes: 1024,
  checksum: VALID_CHECKSUM,
  storageRef: "s3://bucket/report.pdf",
  status: "active",
};

const BASE_PENDING: CreateFileMetadataInput = {
  scope: "org_0190f2a81b3c7abc8123000000000004",
  ownerUsrId: "usr_0190f2a81b3c7abc8123000000000001",
  name: "upload.bin",
  contentType: "application/octet-stream",
  sizeBytes: null,
  checksum: null,
  storageRef: null,
  status: "pending",
};

function store() {
  return new InMemoryFileMetadataStore();
}

describe("InMemoryFileMetadataStore — error taxonomy", () => {
  describe("scope validation", () => {
    it("rejects invalid scope", async () => {
      await expect(store().createFileMetadata({ ...BASE_ACTIVE, scope: "not-an-org" as never }))
        .rejects.toMatchObject({ field: "scope" });
    });
    it("raises InvalidFormatError", async () => {
      await expect(store().createFileMetadata({ ...BASE_ACTIVE, scope: "bad" as never }))
        .rejects.toBeInstanceOf(InvalidFormatError);
    });
  });

  describe("owner_usr_id validation", () => {
    it("rejects invalid ownerUsrId", async () => {
      await expect(store().createFileMetadata({ ...BASE_ACTIVE, ownerUsrId: "bad" as never }))
        .rejects.toMatchObject({ field: "owner_usr_id" });
    });
  });

  describe("name validation", () => {
    it("rejects empty name", async () => {
      await expect(store().createFileMetadata({ ...BASE_ACTIVE, name: "" }))
        .rejects.toMatchObject({ field: "name" });
    });
    it("rejects name > 255 code units", async () => {
      await expect(store().createFileMetadata({ ...BASE_ACTIVE, name: "a".repeat(256) }))
        .rejects.toMatchObject({ field: "name" });
    });
  });

  describe("active create constraints", () => {
    it("rejects active create without size_bytes", async () => {
      await expect(
        store().createFileMetadata({ ...BASE_ACTIVE, sizeBytes: null }),
      ).rejects.toMatchObject({ field: "size_bytes" });
    });
    it("rejects active create without checksum", async () => {
      await expect(
        store().createFileMetadata({ ...BASE_ACTIVE, checksum: null }),
      ).rejects.toMatchObject({ field: "checksum" });
    });
    it("rejects active create without storage_ref", async () => {
      await expect(
        store().createFileMetadata({ ...BASE_ACTIVE, storageRef: null }),
      ).rejects.toMatchObject({ field: "storage_ref" });
    });
    it("rejects bad checksum algo", async () => {
      await expect(
        store().createFileMetadata({ ...BASE_ACTIVE, checksum: { algo: "md5" as never, value: VALID_CHECKSUM.value } }),
      ).rejects.toMatchObject({ field: "checksum" });
    });
    it("rejects checksum value that is not 64 lowercase hex", async () => {
      await expect(
        store().createFileMetadata({ ...BASE_ACTIVE, checksum: { algo: "sha-256", value: "UPPERCASE" } }),
      ).rejects.toMatchObject({ field: "checksum" });
    });
  });

  describe("NotFoundError", () => {
    it("raises NotFoundError for unknown id on getFileMetadata", async () => {
      await expect(
        store().getFileMetadata("file_0190f2a81b3c7abc8123000000000000" as never),
      ).rejects.toBeInstanceOf(NotFoundError);
    });
    it("raises NotFoundError for unknown id on updateFileMetadata", async () => {
      await expect(
        store().updateFileMetadata("file_0190f2a81b3c7abc8123000000000000" as never, { name: "new.pdf" }),
      ).rejects.toBeInstanceOf(NotFoundError);
    });
    it("raises NotFoundError for unknown id on deleteFileMetadata", async () => {
      await expect(
        store().deleteFileMetadata("file_0190f2a81b3c7abc8123000000000000" as never),
      ).rejects.toBeInstanceOf(NotFoundError);
    });
  });

  describe("PreconditionError — lifecycle constraints", () => {
    it("raises PreconditionError when updating a deleted file", async () => {
      const s = store();
      const f = await s.createFileMetadata(BASE_ACTIVE);
      await s.deleteFileMetadata(f.id);
      await expect(s.updateFileMetadata(f.id, { name: "new.pdf" })).rejects.toBeInstanceOf(PreconditionError);
    });
    it("raises PreconditionError when deleting an already-deleted file", async () => {
      const s = store();
      const f = await s.createFileMetadata(BASE_ACTIVE);
      await s.deleteFileMetadata(f.id);
      await expect(s.deleteFileMetadata(f.id)).rejects.toBeInstanceOf(PreconditionError);
    });
    it("raises PreconditionError on pending → active without size_bytes", async () => {
      const s = store();
      const f = await s.createFileMetadata(BASE_PENDING);
      await expect(
        s.updateFileMetadata(f.id, { status: "active", checksum: VALID_CHECKSUM, storageRef: "s3://b/f" }),
      ).rejects.toBeInstanceOf(PreconditionError);
    });
    it("raises PreconditionError on pending → active without checksum", async () => {
      const s = store();
      const f = await s.createFileMetadata(BASE_PENDING);
      await expect(
        s.updateFileMetadata(f.id, { status: "active", sizeBytes: 1024, storageRef: "s3://b/f" }),
      ).rejects.toBeInstanceOf(PreconditionError);
    });
    it("raises PreconditionError on active → pending (invalid transition)", async () => {
      const s = store();
      const f = await s.createFileMetadata(BASE_ACTIVE);
      await expect(
        s.updateFileMetadata(f.id, { status: "pending" as never }),
      ).rejects.toBeInstanceOf(PreconditionError);
    });
  });
});

describe("InMemoryFileMetadataStore — lifecycle invariants", () => {
  it("creates active file with correct shape", async () => {
    const s = store();
    const f = await s.createFileMetadata(BASE_ACTIVE);
    expect(f.id).toMatch(/^file_/);
    expect(f.scope).toBe(BASE_ACTIVE.scope);
    expect(f.ownerUsrId).toBe(BASE_ACTIVE.ownerUsrId);
    expect(f.name).toBe(BASE_ACTIVE.name);
    expect(f.contentType).toBe(BASE_ACTIVE.contentType);
    expect(f.sizeBytes).toBe(BASE_ACTIVE.sizeBytes);
    expect(f.checksum).toEqual(VALID_CHECKSUM);
    expect(f.storageRef).toBe(BASE_ACTIVE.storageRef);
    expect(f.status).toBe("active");
  });

  it("creates pending file with null byte-facts", async () => {
    const s = store();
    const f = await s.createFileMetadata(BASE_PENDING);
    expect(f.status).toBe("pending");
    expect(f.sizeBytes).toBeNull();
    expect(f.checksum).toBeNull();
    expect(f.storageRef).toBeNull();
  });

  it("pending → active sets byte-facts and freezes status", async () => {
    const s = store();
    const f = await s.createFileMetadata(BASE_PENDING);
    const updated = await s.updateFileMetadata(f.id, {
      status: "active",
      sizeBytes: 4096,
      checksum: VALID_CHECKSUM,
      storageRef: "s3://b/upload.bin",
    });
    expect(updated.status).toBe("active");
    expect(updated.sizeBytes).toBe(4096);
    expect(updated.checksum).toEqual(VALID_CHECKSUM);
    expect(updated.storageRef).toBe("s3://b/upload.bin");
  });

  it("pending → deleted is valid (abandoned upload)", async () => {
    const s = store();
    const f = await s.createFileMetadata(BASE_PENDING);
    const deleted = await s.deleteFileMetadata(f.id);
    expect(deleted.status).toBe("deleted");
  });

  it("active → deleted (soft delete) retains record", async () => {
    const s = store();
    const f = await s.createFileMetadata(BASE_ACTIVE);
    await s.deleteFileMetadata(f.id);
    const fetched = await s.getFileMetadata(f.id);
    expect(fetched.status).toBe("deleted");
    expect(fetched.name).toBe(BASE_ACTIVE.name);
    expect(fetched.ownerUsrId).toBe(BASE_ACTIVE.ownerUsrId);
  });

  it("updateFileMetadata mutates name but preserves immutable fields", async () => {
    const s = store();
    const f = await s.createFileMetadata(BASE_ACTIVE);
    const updated = await s.updateFileMetadata(f.id, { name: "final.pdf" });
    expect(updated.name).toBe("final.pdf");
    expect(updated.contentType).toBe(BASE_ACTIVE.contentType);
    expect(updated.ownerUsrId).toBe(BASE_ACTIVE.ownerUsrId);
    expect(updated.scope).toBe(BASE_ACTIVE.scope);
  });

  it("getFileMetadata returns verbatim data", async () => {
    const s = store();
    const f = await s.createFileMetadata(BASE_ACTIVE);
    const fetched = await s.getFileMetadata(f.id);
    expect(fetched).toEqual(f);
  });
});

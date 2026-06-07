// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { generate, isValid } from "@flametrench/ids";

import { InvalidFormatError, NotFoundError, PreconditionError } from "./errors.js";
import type { FileMetadataStore } from "./store.js";
import type {
  Checksum,
  CreateFileMetadataInput,
  FileId,
  FileMetadata,
  OrgId,
  UpdateFileMetadataInput,
  UsrId,
} from "./types.js";

const CHECKSUM_HEX_PATTERN = /^[0-9a-f]{64}$/;

function validateChecksum(c: Checksum, fieldName: string): void {
  if (c.algo !== "sha-256") {
    throw new InvalidFormatError(fieldName, `checksum.algo must be "sha-256", got: ${JSON.stringify(c.algo)}`);
  }
  if (!CHECKSUM_HEX_PATTERN.test(c.value)) {
    throw new InvalidFormatError(fieldName, `checksum.value must be 64 lowercase hex chars`);
  }
}

function validateCreate(input: CreateFileMetadataInput): void {
  if (!isValid(input.scope, "org")) {
    throw new InvalidFormatError("scope", `scope must be a valid org_<32hex>, got: ${String(input.scope)}`);
  }
  if (!isValid(input.ownerUsrId, "usr")) {
    throw new InvalidFormatError("owner_usr_id", `owner_usr_id must be a valid usr_<32hex>, got: ${String(input.ownerUsrId)}`);
  }
  if (typeof input.name !== "string" || input.name.length === 0 || [...input.name].length > 255) {
    throw new InvalidFormatError("name", `name must be 1–255 Unicode code units`);
  }
  if (typeof input.contentType !== "string" || input.contentType.length === 0) {
    throw new InvalidFormatError("content_type", `content_type must be a non-empty string`);
  }

  if (input.status === "active") {
    if (input.sizeBytes === null || input.sizeBytes === undefined) {
      throw new InvalidFormatError("size_bytes", `size_bytes must be set (non-null) when registering as active`);
    }
    if (!Number.isInteger(input.sizeBytes) || input.sizeBytes < 0) {
      throw new InvalidFormatError("size_bytes", `size_bytes must be a non-negative integer`);
    }
    if (input.checksum === null || input.checksum === undefined) {
      throw new InvalidFormatError("checksum", `checksum must be set (non-null) when registering as active`);
    }
    validateChecksum(input.checksum, "checksum");
    if (input.storageRef === null || input.storageRef === undefined || input.storageRef.length === 0) {
      throw new InvalidFormatError("storage_ref", `storage_ref must be set (non-empty) when registering as active`);
    }
  } else if (input.status === "pending") {
    if (input.sizeBytes !== null && input.sizeBytes !== undefined) {
      if (!Number.isInteger(input.sizeBytes) || input.sizeBytes < 0) {
        throw new InvalidFormatError("size_bytes", `size_bytes must be a non-negative integer or null`);
      }
    }
    if (input.checksum !== null && input.checksum !== undefined) {
      validateChecksum(input.checksum, "checksum");
    }
  } else {
    throw new InvalidFormatError("status", `status at create must be "pending" or "active"`);
  }
}

/**
 * Reference in-memory implementation of FileMetadataStore (ADR 0020).
 *
 * Storage-agnostic: storage_ref is stored verbatim and never dereferenced.
 * Soft delete: deleteFileMetadata transitions to status "deleted"; the record
 * is retained and remains fetchable for audit reconstruction and reference integrity.
 *
 * Lifecycle transitions: pending → active, pending → deleted, active → deleted.
 * No transition back to pending; size_bytes/checksum/storage_ref become immutable
 * once set at active.
 */
export class InMemoryFileMetadataStore implements FileMetadataStore {
  private readonly files = new Map<FileId, FileMetadata>();

  async createFileMetadata(input: CreateFileMetadataInput): Promise<FileMetadata> {
    validateCreate(input);
    const id = generate("file") as FileId;
    const now = new Date();
    const file: FileMetadata = {
      id,
      scope: input.scope as OrgId,
      ownerUsrId: input.ownerUsrId as UsrId,
      name: input.name,
      contentType: input.contentType,
      sizeBytes: input.sizeBytes ?? null,
      checksum: input.checksum ? { ...input.checksum } : null,
      storageRef: input.storageRef ?? null,
      status: input.status,
      createdAt: now,
      updatedAt: now,
    };
    this.files.set(id, file);
    return file;
  }

  async getFileMetadata(id: FileId): Promise<FileMetadata> {
    return this.getOrThrow(id);
  }

  async updateFileMetadata(id: FileId, input: UpdateFileMetadataInput): Promise<FileMetadata> {
    const f = this.getOrThrow(id);

    if (f.status === "deleted") {
      throw new PreconditionError(`Cannot update a deleted file (id: ${id})`);
    }

    const updatedStatus = input.status ?? f.status;

    if (updatedStatus === "active" && f.status === "pending") {
      const newSizeBytes = input.sizeBytes !== undefined ? input.sizeBytes : f.sizeBytes;
      const newChecksum = input.checksum !== undefined ? input.checksum : f.checksum;
      const newStorageRef = input.storageRef !== undefined ? input.storageRef : f.storageRef;
      if (newSizeBytes === null) {
        throw new PreconditionError(`size_bytes must be set (non-null) on pending → active transition`);
      }
      if (newChecksum === null) {
        throw new PreconditionError(`checksum must be set (non-null) on pending → active transition`);
      }
      validateChecksum(newChecksum, "checksum");
      if (!newStorageRef) {
        throw new PreconditionError(`storage_ref must be set (non-empty) on pending → active transition`);
      }
    }

    if (input.name !== undefined && (typeof input.name !== "string" || input.name.length === 0 || [...input.name].length > 255)) {
      throw new InvalidFormatError("name", `name must be 1–255 Unicode code units`);
    }

    if (f.status === "active" && updatedStatus === "pending") {
      throw new PreconditionError(`Cannot transition from active back to pending`);
    }

    let sizeBytes = f.sizeBytes;
    let checksum = f.checksum;
    let storageRef = f.storageRef;

    if (f.status === "pending" && updatedStatus === "active") {
      sizeBytes = input.sizeBytes !== undefined ? input.sizeBytes : f.sizeBytes;
      checksum = input.checksum !== undefined ? input.checksum : f.checksum;
      storageRef = input.storageRef !== undefined ? input.storageRef : f.storageRef;
    }

    const updated: FileMetadata = {
      ...f,
      name: input.name !== undefined ? input.name : f.name,
      status: updatedStatus,
      sizeBytes,
      checksum: checksum ? { ...checksum } : null,
      storageRef,
      updatedAt: new Date(),
    };
    this.files.set(id, updated);
    return updated;
  }

  async deleteFileMetadata(id: FileId): Promise<FileMetadata> {
    const f = this.getOrThrow(id);
    if (f.status === "deleted") {
      throw new PreconditionError(`File is already deleted (id: ${id})`);
    }
    const updated: FileMetadata = { ...f, status: "deleted", updatedAt: new Date() };
    this.files.set(id, updated);
    return updated;
  }

  private getOrThrow(id: FileId): FileMetadata {
    const f = this.files.get(id);
    if (!f) throw new NotFoundError(`File not found: ${id}`);
    return f;
  }
}

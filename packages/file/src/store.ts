// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import type { CreateFileMetadataInput, FileId, FileMetadata, OrgId, UpdateFileMetadataInput } from "./types.js";

/**
 * The FileMetadataStore interface is the contract every file-metadata backend fulfills.
 *
 * Two hard lines (ADR 0020):
 *   1. Storage-agnostic — `storage_ref` is an opaque adopter pointer, stored verbatim, never dereferenced.
 *   2. Access via `authz` — the primitive does not define a parallel ACL; access is `check()` on the file object.
 *
 * Cross-scope non-disclosure: `get`/`update`/`delete` targeting a file in a foreign scope MUST
 * raise the same `NotFoundError` — no presence differential.
 *
 * `deleteFileMetadata` is a soft delete: the record is RETAINED at status `"deleted"`.
 *
 * `createFileMetadata`/`updateFileMetadata`/`deleteFileMetadata` MUST emit `aud` events (wired by adopters).
 */
export interface FileMetadataStore {
  createFileMetadata(input: CreateFileMetadataInput): Promise<FileMetadata>;
  getFileMetadata(id: FileId): Promise<FileMetadata>;
  updateFileMetadata(id: FileId, input: UpdateFileMetadataInput): Promise<FileMetadata>;
  deleteFileMetadata(id: FileId): Promise<FileMetadata>;
}

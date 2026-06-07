// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * @flametrench/file — file-metadata primitive.
 *
 * Storage-agnostic metadata tracking with lifecycle (pending/active/deleted)
 * and authz-based access. Stores and returns `storage_ref` verbatim.
 * See ADR 0020.
 *
 * Exports:
 *   - Entity types matching the wire contract.
 *   - A FileMetadataStore interface — the contract every backend fulfills.
 *   - An InMemoryFileMetadataStore implementation — reference / tests.
 *   - Error classes with spec-stable `code` identifiers.
 */

export type {
  Checksum,
  CreateFileMetadataInput,
  FileId,
  FileMetadata,
  FileStatus,
  OrgId,
  UpdateFileMetadataInput,
  UsrId,
} from "./types.js";

export type { FileMetadataStore } from "./store.js";

export { InMemoryFileMetadataStore } from "./in-memory.js";

export { FileError, InvalidFormatError, NotFoundError, PreconditionError } from "./errors.js";

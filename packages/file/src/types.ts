// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

export type FileId = `file_${string}`;
export type OrgId = `org_${string}`;
export type UsrId = `usr_${string}`;

export type FileStatus = "pending" | "active" | "deleted";

export interface Checksum {
  algo: "sha-256";
  value: string;
}

export interface FileMetadata {
  id: FileId;
  scope: OrgId;
  ownerUsrId: UsrId;
  name: string;
  contentType: string;
  sizeBytes: number | null;
  checksum: Checksum | null;
  storageRef: string | null;
  status: FileStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateFileMetadataInput {
  scope: OrgId;
  ownerUsrId: UsrId;
  name: string;
  contentType: string;
  sizeBytes: number | null;
  checksum: Checksum | null;
  storageRef: string | null;
  status: "pending" | "active";
}

export interface UpdateFileMetadataInput {
  name?: string;
  status?: "active" | "deleted";
  sizeBytes?: number | null;
  checksum?: Checksum | null;
  storageRef?: string | null;
}

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

export type FlagId = `flag_${string}`;
export type OrgId = `org_${string}`;
export type UsrId = `usr_${string}`;

export interface AuthzRule {
  kind: "authz";
  relation: string;
  object: { type: string; id: string };
  variant: boolean;
}

export interface PercentageRule {
  kind: "percentage";
  basis_points: number;
  variant: boolean;
}

export type Rule = AuthzRule | PercentageRule;

export interface Flag {
  id: FlagId;
  scope: OrgId;
  key: string;
  enabled: boolean;
  default_variant: boolean;
  rules: Rule[];
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateFlagInput {
  scope: OrgId;
  key: string;
  enabled: boolean;
  default_variant: boolean;
  rules: Rule[];
}

export interface UpdateFlagInput {
  enabled?: boolean;
  default_variant?: boolean;
  rules?: Rule[];
}

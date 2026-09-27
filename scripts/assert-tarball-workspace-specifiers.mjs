// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// The publish workflow's publish job runs `npm publish <tgz>` on tarballs
// built by a separate, uncredentialed build job. Publishing an existing
// tarball does NOT run package lifecycle scripts, so prepublishOnly
// (scripts/assert-pnpm.mjs) never fires in that job — it only protects a
// `npm publish` invoked directly against a package directory.
//
// This script is the replacement guard for the tarball path: it inspects
// each packed package.json and fails if any dependency field still carries
// an unresolved `workspace:` specifier. `pnpm pack`/`pnpm publish` rewrite
// those to real versions; a bare `npm pack` or a misconfigured build step
// would not, and would ship the same broken installs as the 2026-04-29
// incident (see assert-pnpm.mjs).
//
// Usage: node assert-tarball-workspace-specifiers.mjs <tarball.tgz> [...]

import { spawnSync } from "node:child_process";

const DEP_FIELDS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
];

function readPackageJsonFromTarball(tarballPath) {
  const result = spawnSync(
    "tar",
    ["-xzOf", tarballPath, "package/package.json"],
    { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 }
  );

  if (result.status !== 0) {
    throw new Error(
      `failed to read package/package.json from ${tarballPath}: ${result.stderr}`
    );
  }

  return JSON.parse(result.stdout);
}

function findWorkspaceSpecifiers(pkgJson) {
  const offenders = [];

  for (const field of DEP_FIELDS) {
    const deps = pkgJson[field];
    if (!deps) continue;

    for (const [name, range] of Object.entries(deps)) {
      if (typeof range === "string" && range.startsWith("workspace:")) {
        offenders.push(`${field}.${name} = "${range}"`);
      }
    }
  }

  return offenders;
}

function main(tarballPaths) {
  if (tarballPaths.length === 0) {
    console.error("usage: assert-tarball-workspace-specifiers.mjs <tarball.tgz> [...]");
    process.exit(1);
  }

  let failed = false;

  for (const tarballPath of tarballPaths) {
    const pkgJson = readPackageJsonFromTarball(tarballPath);
    const offenders = findWorkspaceSpecifiers(pkgJson);

    if (offenders.length > 0) {
      failed = true;
      console.error("");
      console.error(`ERROR: ${tarballPath} (${pkgJson.name}@${pkgJson.version}) has unresolved workspace: specifiers:`);
      for (const offender of offenders) {
        console.error(`  ${offender}`);
      }
      console.error("");
      console.error(
        "This tarball must not be published — installing it will break for"
      );
      console.error(
        "downstream adopters. Rebuild with `pnpm pack`, not `npm pack`."
      );
    } else {
      console.log(`OK: ${tarballPath} (${pkgJson.name}@${pkgJson.version}) has no workspace: specifiers.`);
    }
  }

  process.exit(failed ? 1 : 0);
}

main(process.argv.slice(2));

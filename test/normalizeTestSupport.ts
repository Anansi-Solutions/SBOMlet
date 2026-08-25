import {
  asPurl,
  asRawLicense,
  type CanonicalDependencies,
  type LicenseClaim,
  type LicenseClaimKind,
  type PackageEntry,
} from "../src/model/dependencies";

export const claim = (raw: string, kind: LicenseClaimKind = "spdx-id"): LicenseClaim => ({
  raw: asRawLicense(raw),
  kind,
  source: "generator",
});

export const pkg = (name: string, version: string, claims: LicenseClaim[]): PackageEntry => ({
  purl: asPurl(`pkg:npm/${name}@${version}`),
  name,
  version,
  occurrences: [{ target: "frontend", isDevDependency: false }],
  licenseClaims: claims,
  scope: "app",
});

/** OS-scope variant of {@link pkg} (a pkg:deb row): scope "os", os target. */
export const osPkg = (name: string, version: string, claims: LicenseClaim[]): PackageEntry => ({
  purl: asPurl(`pkg:deb/debian/${name}@${version}`),
  name,
  version,
  occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
  licenseClaims: claims,
  scope: "os",
});

export const modelOf = (...entries: PackageEntry[]): CanonicalDependencies => ({
  packages: entries,
});

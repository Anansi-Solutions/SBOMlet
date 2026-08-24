import type {
  CanonicalDependencies,
  LicenseClaim,
  LicenseClaimKind,
  PackageEntry,
  RawLicense,
} from "../src/model/dependencies";

export const claim = (raw: string, kind: LicenseClaimKind = "spdx-id"): LicenseClaim => ({
  raw: raw as RawLicense,
  kind,
  source: "generator",
});

export const pkg = (name: string, version: string, claims: LicenseClaim[]): PackageEntry => ({
  purl: `pkg:npm/${name}@${version}`,
  name,
  version,
  occurrences: [{ target: "frontend", isDevDependency: false }],
  licenseClaims: claims,
  scope: "app",
});

/** OS-scope variant of {@link pkg} (a pkg:deb row): scope "os", os target. */
export const osPkg = (name: string, version: string, claims: LicenseClaim[]): PackageEntry => ({
  purl: `pkg:deb/debian/${name}@${version}`,
  name,
  version,
  occurrences: [{ target: "docker:img/Dockerfile", isDevDependency: false }],
  licenseClaims: claims,
  scope: "os",
});

export const modelOf = (...entries: PackageEntry[]): CanonicalDependencies => ({
  packages: entries,
});

/**
 * The OS/system-package purl-ecosystem allowlist.
 *
 * A container image scan (the syft collector) keeps EVERY component across EVERY ecosystem it finds
 * — deb/apk/rpm/alpm base-image packages alongside whatever npm/pypi/golang/cargo/nuget/maven
 * packages an application layer installed into the image. The collector does not distinguish them;
 * this set is the deliberate, curated discriminator that does: it names the Linux distro
 * package-manager purl types a base image installs its own plumbing through, so a package on this
 * list is routine system content and everything else is an application dependency baked into the
 * image.
 *
 * An ALLOWLIST, not a denylist: any purl type absent here — recognized or not — is treated as
 * application-level. That is the safe direction, since an unrecognized ecosystem is far more likely
 * to be someone's dependency than an undocumented system-package manager.
 *
 * Shared by the container re-scope transform (the engine carve-out) and the render layer's
 * per-container System/Application table split — one discriminator, so the two views can never
 * disagree about which packages are routine.
 */
export const OS_PACKAGE_ECOSYSTEMS: ReadonlySet<string> = new Set([
  "deb",
  "apk",
  "rpm",
  "alpm",
]);

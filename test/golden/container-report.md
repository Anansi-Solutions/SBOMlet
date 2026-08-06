# Third-Party Licenses

<!-- AUTO-GENERATED - do not edit. Regenerate with: task generate -->

Copyleft notice rules are configured in policy.toml.

**Package counts:**

- Total packages: 8
- deb: 4
- golang: 2
- npm: 2
- Production packages: 1
- Development-only packages: 1
- Container packages: 6
- Unknown license: 0

## Problematic licenses

| Severity | Rule                   | Name           | Ecosystem | Version | License           | Used in                        | Why                                                                               | Reason                                                                                                                                                                                                                                                                                                |
| -------- | ---------------------- | -------------- | --------- | ------- | ----------------- | ------------------------------ | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| fail     | default:agpl-container | metrics-daemon | golang    | 1.2.0   | AGPL-3.0-only     | docker:services/api/Dockerfile | —                                                                                 | AGPL leaf in elected "AGPL-3.0-only" is a network-copyleft obligation (AGPL section 13 reaches server-side use) in container system package "docker:services/api/Dockerfile" — not routine base-image copyleft; add a scoped \[\[compatible\]\] rule if this container is accepted                    |
| fail     | default:agpl-container | relay-agent    | golang    | 0.4.0   | AGPL (imprecise)  | docker:tools/build/Dockerfile  | —                                                                                 | imprecise license family "AGPL" in container system package "docker:tools/build/Dockerfile" could carry the AGPL network-copyleft obligation (section 13 reaches server-side use) — disambiguate via a \[\[clarify\]\] override, or add a scoped \[\[compatible\]\] rule if the container is accepted |
| fail     | default:copyleft       | chart-render   | npm       | 2.3.1   | LGPL-3.0-or-later | apps/web                       | pkg:npm/web-root@1.0.0 → pkg:npm/dashboard-kit@1.0.0 → pkg:npm/chart-render@2.3.1 | copyleft license "LGPL-3.0-or-later" (from "LGPL-3.0-or-later") is not allowed in "apps/web" and no compatible rule or workspace suppression applies                                                                                                                                                  |

_Non-blocking: 3 copyleft warning(s) (dev/os-downgraded or suppressed). See the sections below._

## Copyleft and special notices

The packages listed below carry copyleft or special license obligations in at least one non-suppressed workspace.

| Name    | Ecosystem | Version | License           | Used in  | Why |
| ------- | --------- | ------- | ----------------- | -------- | --- |
| doc-gen | npm       | 1.0.0   | LGPL-2.1-or-later | apps/web | —   |

## Imprecise licenses (review / disambiguate)

These packages report an ambiguous license family that was NOT guessed to a precise SPDX id. Disambiguate each via a policy `[[clarify]]` override.

| Name        | Ecosystem | Version | License          | Used in                       |
| ----------- | --------- | ------- | ---------------- | ----------------------------- |
| relay-agent | golang    | 0.4.0   | AGPL (imprecise) | docker:tools/build/Dockerfile |

## Containers

| Container                      | Classification | Packages |
| ------------------------------ | -------------- | -------- |
| docker:services/api/Dockerfile | production     | 5        |
| docker:tools/build/Dockerfile  | development    | 2        |

## Production dependencies

| Name         | Ecosystem | Version | License           | Used in  |
| ------------ | --------- | ------- | ----------------- | -------- |
| chart-render | npm       | 2.3.1   | LGPL-3.0-or-later | apps/web |

### Container: docker:services/api/Dockerfile

| Name           | Ecosystem | Version  | License           |
| -------------- | --------- | -------- | ----------------- |
| bash           | deb       | 5.2-6    | GPL-3.0-or-later  |
| coreutils      | deb       | 9.1-1    | GPL-3.0-or-later  |
| libc6          | deb       | 2.36-9   | LGPL-2.1-or-later |
| metrics-daemon | golang    | 1.2.0    | AGPL-3.0-only     |
| zlib1g         | deb       | 1.2.13-1 | Zlib              |

## Development-only dependencies

| Name    | Ecosystem | Version | License           | Used in  |
| ------- | --------- | ------- | ----------------- | -------- |
| doc-gen | npm       | 1.0.0   | LGPL-2.1-or-later | apps/web |

### Container: docker:tools/build/Dockerfile

| Name        | Ecosystem | Version  | License          |
| ----------- | --------- | -------- | ---------------- |
| relay-agent | golang    | 0.4.0    | AGPL (imprecise) |
| zlib1g      | deb       | 1.2.13-1 | Zlib             |

/**
 * Collector tool identity. The literal version is the pin - it lives in mise.toml
 * (`"pipx:scancode-toolkit[full]" = "32.5.0"`) like every other tool this project depends on, and
 * is asserted at runtime from the scan output's own `headers[0].tool_version` (the SYFT_TOOL
 * comment voice, dockerOs.ts) so a version bump - or a substituted binary - must be conscious,
 * never silent.
 */
export const SCANCODE_TOOL = {
  name: "scancode-toolkit",
  version: "32.5.0",
} as const;

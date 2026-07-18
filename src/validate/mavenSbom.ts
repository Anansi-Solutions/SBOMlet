/**
 * arktype boundary for the committed maven.sbom.json CycloneDX document
 * (loud-fail posture — a committed artifact under this fixed name must never
 * silently misparse). Only the fields the collector consumes are declared:
 * bomFormat, components, and metadata.component.purl; every other field
 * (specVersion, serialNumber, dependencies, ...) still reaches the merge
 * unchanged, since the collector passes the raw committed bytes through
 * rather than re-emitting a document built from this narrow.
 */
import { type } from "arktype";

export const MavenSbomDocument = type({
  "bomFormat?": "string",
  "components?": "unknown[]",
  "metadata?": { "component?": { "purl?": "string" } },
});

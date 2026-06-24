# Writing-style guide

This guide is for anyone writing or editing the documentation in this directory.
It exists so the docs read in one voice and stay easy to navigate. Follow it.

## Who we write for

Three readers, each with their own track. Write each page for one of them and
say, near the top, who that is.

- **Operator** — adds the tool to a repository, runs it, wires it into CI. Wants
  to get a working inventory and a passing gate, and to fix things when they
  break.
- **Policy author / compliance reviewer** — writes `.sbomlet.toml`, reads the
  generated documents, and decides what to do about a flagged dependency. Cares
  about licences and obligations, not about the tool's internals.
- **Contributor** — changes the tool itself. Wants the architecture, the data
  model, and the reasoning behind the design.

## The four kinds of page (Diátaxis)

Every page is one of these. Mixing them is the main way docs become hard to use.

- **Tutorial** — learning by doing. A guided first run, start to finish. Warm,
  encouraging, concrete. (`getting-started.md`)
- **How-to guide** — a recipe for a task the reader already has in mind.
  Imperative and second person: "Add a `[[deny]]` entry…". (`guides/`)
- **Reference** — look-up material: flags, schema fields, exit codes, output
  layout. Terse, complete, scannable. Tables over prose. (`reference/`)
- **Explanation** — understanding. Why the tool is shaped this way. Calm, third
  person, narrative. (`explanation/`, including the ADRs)

## Voice

Write the way a thoughtful colleague explains something at a whiteboard.

- When in doubt, be warmer and plainer. Short sentences. Ordinary words.
- Cut filler and buzzwords. No "leverage", "robust", "seamless", "powerful",
  "in the world of", "it's worth noting that", "simply", "just". If a sentence
  survives deletion of its adjectives, delete them.
- Avoid the tells of generated prose: a bold label followed by a colon and a
  restatement; relentless rule-of-three lists; "Not only X, but also Y"; an
  em-dash in every sentence; closing every section with a grand summary.
- State a goal or fact plainly. Don't reach for metaphor or personification to
  make a point land, and skip the punchy one-line closer — both read as
  generated. Write "avoid wrong answers; clearly surface ambiguities that need
  analysis", not "a loud gap or an honest dash beats a confident wrong answer".
  A document has no "instinct", and nobody writes "an honest dash".
- Drop the "X beats Y" / "prefer X over Y" flourish when you're just stating a
  point; say the point.
- Use jargon only when it earns its place. Define a domain term the first time
  it appears and link it to the glossary. Prefer "the dependency that pulled it
  in" over "the introducer" until the reader has met the term.

## The cardinal rule: keep intention and implementation apart

A reader wants the *idea* first. The *where-in-the-code* is a reference they
consult only if they're changing that code. Never braid the two together, and
never sprinkle `file.ts:33` citations through an explanation.

Structure any implementation-bearing passage in three moves, in order:

1. **The intention that holds across the board** — the rule as it applies to
   every module.
2. **The exceptions** — where a specific module departs from it, and why.
3. **The source**, as a short trailing list — only after the prose, never inside
   it.

Avoid this (idea, exception, and citation all mashed together):

> **No timestamps.** The Markdown header carries the **regenerate command**, not
> a date (`task generate`; markdown.ts:33-34). The CycloneDX document
> omits `serialNumber` and `metadata.timestamp` (cyclonedx.ts:164-174). The
> docker SBOM is digest-pinned, not time-stamped.

Write this instead:

> Nothing the tool writes carries a timestamp. A timestamp would change on every
> run, so `check` could never tell a real change from the clock ticking. Each
> document instead records *how to regenerate it*, which only changes when the
> command does.
>
> The exceptions are shaped by their formats. The Markdown header names the
> regenerate command in place of a date. The CycloneDX export drops the two
> fields that would otherwise carry a time — the document serial number and the
> metadata timestamp. The Docker SBOM pins each image by content digest, which
> is stable, rather than by scan time.
>
> Source: `render/markdown.ts`, `render/cyclonedx.ts`, `collectors/dockerOs.ts`.

The second version lets a reader who only wants the idea stop after the first
paragraph, and points a contributor at the right files without making everyone
else read line numbers.

## Source references

Cite the code only where a reader changing it would thank you for the pointer.
They go stale, so make them as durable as the page can bear.

- Never cite line numbers — they rot the fastest. Cite the most stable thing
  that still locates the code: a directory (`normalize/`), a module
  (`collectors/terraform.ts`), or a well-named function
  (`absentModulesJsonShouldFail`). When an idea spans several files, name the
  directory or the concept rather than listing them all.
- Put references in a trailing `Source:` line, never inside the prose.
- Omit them where they add nothing — operator and policy pages, where the
  reader never opens the code.

## Formatting

- One `# H1` per file: the page title.
- `inline code` for filenames, flags, commands, and identifiers.
- Every command is real and runnable as written.
- Reference material goes in tables. Explanation goes in prose.
- Link generously between pages, and from a term to the glossary on first use.

## Before you commit a page

- Could the intended reader find their answer without reading another page first?
- Is every kind-of-page rule respected (no reference buried in an explanation)?
- Did you remove the citations from inside the prose?
- Read it aloud. If a sentence sounds like a brochure or a model, rewrite it.

# Gitway log format — stability statement

This document spells out the stability tier of every observable log
surface Gitway emits.

## Tiers

| Tier | Surface | Shape |
|---|---|---|
| **Stable** | The single-line `gitway diag …` failure record on stderr (NFR-24). | Documented field set: `ts=…`, `pid=…`, `argv=…`, `exit=…`, `reason=…`, `config_source=…`. |
| **Stable** | JSON-mode error envelope on stderr (`{"metadata":…,"error":…}`). | See `docs/json-schema.md`. |
| **Advisory** | `-v` / `-vv` / `-vvv` / `--debug-format=json` / `--debug-categories=…` log streams (FR-65..FR-69). | Field set may evolve between minor releases. |
| **Advisory** | Human-readable `gitway: …` status lines on stderr. | Wording, formatting, and ordering may change at any time. |

## Why advisory for `-vvv`

The `tracing` event surface is a debugging tool.  Pinning the field
set would freeze the diagnostics layer and make it harder to add
new instrumentation in response to user reports.  Tools that scrape
`-vvv` output for automation are doing so at their own risk; the
recommended programmatic surface is `--json` (envelope-stable per
`docs/json-schema.md`) or `gitway describe` (catalogue-stable per
the same).

## What "advisory" means in practice

- Field names like `kex_algorithm`, `auth_method`, `attempt`,
  `elapsed_ms` may be renamed or restructured in any minor release.
- New events may be added without warning.
- Existing events may be removed in a minor release if they prove
  redundant; we'll prefer renaming over removal.
- The categories themselves (`CAT_KEX`, `CAT_AUTH`, `CAT_CHANNEL`,
  `CAT_CONFIG`, `CAT_RETRY`) are stable — adding a new category is
  additive, removing one is a major-version event.

## What "stable" means for the diag line

The single-line `gitway diag …` record (NFR-24) is parsed by triage
tooling and must not change shape.  Its fields:

- `ts=` — ISO-8601 UTC timestamp
- `pid=` — process ID
- `argv=` — full command line, space-joined
- `exit=` — integer exit code
- `reason=` — short error code (matches the `error.code` field of
  the JSON envelope)
- `config_source=` — semicolon-separated list of `~/.ssh/config`
  files this invocation consulted (M12.8 / NFR-24); empty when
  `--no-config` is set

Adding a new field is allowed in a minor release; renaming or
removing a field is a major-version change.

# Gitway JSON envelope — `schema_version` policy

This document is the public contract for every `--json` and
always-JSON surface Gitway exposes.  Downstream tooling — agents,
MCP discovery layers, CI parsers, log shippers — can pin against
this contract.

**Frozen at:** `1.0.0` (Gitway v1.0.0).
**Source of truth:** [`JSON_SCHEMA_VERSION`][src] in
`gitway-cli/src/main.rs`.

[src]: ../gitway-cli/src/main.rs

## Envelope shape

Every JSON-emitting Gitway surface produces one of two shapes:

### Success envelope

```jsonc
{
  "metadata": {
    "tool": "gitway",
    "schema_version": "1.0.0",
    "version": "<gitway CARGO_PKG_VERSION>",
    "command": "<the command, e.g. `gitway hosts list`>",
    "timestamp": "<ISO-8601 UTC>"
  },
  "data": { /* command-specific keys */ }
}
```

### Error envelope

```jsonc
{
  "metadata": {
    "tool": "gitway",
    "schema_version": "1.0.0",
    "version": "<gitway CARGO_PKG_VERSION>",
    "command": "<the full argv joined by spaces>",
    "timestamp": "<ISO-8601 UTC>"
  },
  "error": {
    "code": "<machine-readable error code>",
    "exit_code": <integer per docs/exit-codes.md>,
    "message": "<human-readable message>",
    "hint": "<actionable suggestion>"
  }
}
```

### `gitway schema` and `gitway describe`

These two surfaces are themselves the stable contract — they expose
`schema_version` directly at the top level rather than under
`metadata`.  Their shape:

```jsonc
{
  "tool": "gitway",
  "schema_version": "1.0.0",
  "version": "<gitway CARGO_PKG_VERSION>",
  /* command / flag / capability metadata */
}
```

## Bump policy

| Bump | When | Examples |
|---|---|---|
| **Patch** (`1.0.x`) | Additive, non-breaking field additions inside `data` or new commands. | Adding a new field to `gitway hosts list` `data`. |
| **Minor** (`1.x.0`) | Additive structural changes — new top-level keys alongside `metadata`/`data`/`error`. | Adding a `warnings` array to the success envelope. |
| **Major** (`x.0.0`) | Any breaking change — renamed key, changed type, removed field. | Renaming `metadata.command` to `metadata.invocation`. |

A bump always updates `JSON_SCHEMA_VERSION` in
`gitway-cli/src/main.rs` first; CI then enforces the new shape via
the snapshot test in `gitway-cli/tests/schema_freeze.rs` (when
present).

## Surfaces covered

The `1.0.0` contract covers the following commands' `--json`
output:

- `gitway --test --json`
- `gitway --install --json`
- `gitway schema` (always JSON)
- `gitway describe` (always JSON)
- `gitway config show --json`
- `gitway hosts {add,revoke,list} --json`
- `gitway list-algorithms --json`
- `gitway keygen {generate,fingerprint,extract-public,change-passphrase,verify} --json`
- `gitway agent {add,list,remove,lock,unlock,stop} --json`
- `gitway sign --json`
- All error paths in JSON-mode (auto-selected by `--json`,
  `--format=json`, or any of the agent env vars in
  `docs/log-format.md`).

## Example — `gitway --test --json`

```sh
gitway --test --json --port 22 github.com
```

```jsonc
{
  "metadata": {
    "tool": "gitway",
    "schema_version": "1.0.0",
    "version": "1.0.0",
    "command": "gitway --test --host github.com",
    "timestamp": "2026-05-05T10:14:32Z"
  },
  "data": {
    "host": "github.com",
    "port": 22,
    "host_key_verified": true,
    "fingerprint": "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
    "authenticated": true,
    "username": "git",
    "banner": null,
    "cert_authorities": [],
    "revoked": [],
    "retry_attempts": []
  }
}
```

## Stability statement

The `1.0.0` envelope contract is **stable** under SemVer.  Patch
releases (1.0.x) will only add fields.  Tools that strict-parse the
envelope (validating shape and rejecting unknown fields) **must
not** treat unknown additions as errors.  Tools that compare against
this document should pin against the version reported by
`gitway describe.schema_version` rather than the binary's own
version.

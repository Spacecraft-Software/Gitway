# Gitway error-hint contract — `tips-thinking`

Gitway follows the Spacecraft Software agentic-CLI convention of pairing every
error with an actionable `hint` ("what to do next") line.  The
hint surface is **advisory** for v1.0 — text content may change
between releases.

## Surface

### Human mode (default)

Two lines on stderr:

```text
gitway: error: <message>
gitway: what to do: <hint>
```

The `what to do:` prefix is fixed; the hint text after it is
advisory.

### JSON mode

The error envelope (`docs/json-schema.md`) carries the hint as a
sibling of the message:

```jsonc
{
  "error": {
    "code": "no_key_found",
    "exit_code": 3,
    "message": "no SSH identity key found on disk",
    "hint": "Run `gitway keygen generate` or set --identity"
  }
}
```

## Stability tier

| Surface | Tier |
|---|---|
| The `error.code` field (machine-readable) | **Stable** — codes added or kept; never renamed or removed in 1.x. |
| The `error.exit_code` field | **Stable** — see `docs/exit-codes.md`. |
| The `error.message` field | **Advisory** — wording may change. |
| The `error.hint` field | **Advisory** — wording, length, and presence may change. |
| The human-mode `gitway: error:` and `gitway: what to do:` line prefixes | **Stable** — exact strings. |

## Why advisory

The hint surface is a UX layer.  Pinning the wording would make it
hard to refine messages in response to user feedback.  A tool that
needs to react to a specific failure should match on `error.code`
(stable), not on `error.message` or `error.hint`.

## Empty hints

Some error variants do not have a meaningful hint and emit `null`
(JSON) or skip the `gitway: what to do:` line (human).  Tools must
tolerate `null` hints in v1.x.

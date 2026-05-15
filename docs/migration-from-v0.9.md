# Migrating from Gitway v0.9 to v1.0

Gitway v1.0 is a stabilization release of the v0.9 line.  No
breaking changes are required for end users (`gitway --test`,
`gitway --install`, transport via `core.sshCommand=gitway` keep
working unchanged).  The migration story is two-fold:

1. **End users** — pick up the new flags and subcommands at your
   own pace.  Existing config and workflows keep working.
2. **Library users of `gitway-lib`** — the deprecation timeline
   is now firm.  Switch direct `gitway_lib::*` imports to
   `anvil_ssh::*`.

## End-user changes since v0.9

### New top-level flags

All additive; defaults preserve v0.9 behavior.

| Flag | Milestone | What it does |
|---|---|---|
| `--no-config` | M12 | Skip all `~/.ssh/config` files. |
| `--proxy-command <CMD>` | M13 | Run `<CMD>` as the SSH transport (overrides `ssh_config`).  Pass `none` to disable an inherited setting. |
| `-J`, `--jump-host <HOST>` | M13 | Repeatable bastion chain (mirrors OpenSSH `-J`). |
| `--debug-format <human\|json>` | M15 | Choose the `-vvv` log format on stderr. |
| `--debug-categories <list>` | M15 | Comma-separated category filter (`kex`, `auth`, `channel`, `config`, `retry`, `russh`, `anvil_ssh::*`). |
| `--connect-timeout <SECS>` | M18 | Per-attempt TCP connect deadline. |
| `--attempts <N>` | M18 | Total connection attempts incl. the first.  `1` disables retry. |
| `--max-retry-window <SECS>` | M18 | Hard ceiling on total retry wall-clock time. |
| `--kex <LIST>` | M17 | Override KEX algorithm preference (`+/-/^/replace` syntax). |
| `--ciphers <LIST>` | M17 | Override cipher preference. |
| `--macs <LIST>` | M17 | Override MAC preference. |
| `--host-key-algorithms <LIST>` | M17 | Override host-key algorithm preference. |

### New subcommands

| Subcommand | Milestone | What it does |
|---|---|---|
| `gitway config show <host>` | M12 | Mirror of `ssh -G <host>`; renders the resolved config in human or JSON form. |
| `gitway hosts add <host>` | M19 | Capture a host's fingerprint and append a known_hosts pin (hashed if file is hashed). |
| `gitway hosts revoke <host\|fingerprint>` | M19 | Prepend a `@revoked` line. |
| `gitway hosts list` | M19 | Aggregate embedded + direct + cert-authority + revoked entries.  Supports `--format=json`. |
| `gitway list-algorithms` | M17 | Catalogue of supported algorithms tagged `default` / `available` / `denylisted`. |

### JSON envelope contract

The `--json` envelope is now contractually frozen at
`schema_version = "1.0.0"`.  See `docs/json-schema.md` for the
exact shape and bump policy.  Existing v0.9 envelopes get an
additional `metadata.schema_version` field; no existing fields
were renamed or removed.

If you parse Gitway's `--json` output strictly (rejecting unknown
keys), update your parser to tolerate `metadata.schema_version`,
`metadata.tool` (now always `"gitway"`), and any new `data` keys
documented per command.

### Agent env-var detection

`AI_AGENT=1`, `AGENT=1`, and `CI=true` (case-insensitive) already
auto-selected JSON mode in v0.9.  v1.0 adds three more:

- `CLAUDECODE=1` (Claude Code harness)
- `CURSOR_AGENT=1` (Cursor's agent mode)
- `GEMINI_CLI=1` (Google Gemini CLI)

If you previously set `AI_AGENT=1` to opt into JSON mode under one
of these tools, keep doing so — the new env vars are additive
auto-detection only.

### Exit codes

Codes 0–4 are unchanged.  Two specialized codes are now documented
explicitly (they were already used in v0.9 but were not in the
public exit-code table):

- **73** — user declined a confirmation prompt (`gitway hosts add`).
- **78** — interactive input required but unavailable (`gitway hosts
  add` without `--yes`).

See `docs/exit-codes.md`.

## Library users — `gitway-lib` deprecation timeline

The `gitway_lib` crate is now a thin compat shim over `anvil-ssh`
(see PRD §7.1).  As of v1.0, **the shim is preserved but
deprecated**; we plan to remove it in v2.0.

### v1.0 status

```toml
[dependencies]
gitway-lib = { version = "1.0", path = "..." }   # still works
anvil-ssh  = "1.0"                               # preferred
```

```rust
// Both still work in v1.0:
use gitway_lib::AnvilSession;   // re-export through the shim
use anvil_ssh::AnvilSession;    // direct
```

### Migration steps

For every direct `gitway_lib::*` import:

1. Replace the path: `gitway_lib::X` → `anvil_ssh::X`.
2. The type names already use the `Anvil*` form post-M11.5; if you
   see legacy `Gitway*` aliases (`GitwaySession`,  `GitwayConfig`,
   `GitwayError`), update them to the canonical `Anvil*` names.
3. Update your `Cargo.toml`: drop the `gitway-lib` dependency, add
   `anvil-ssh = "1.0"`.

### Deprecation timeline

| Version | `gitway-lib` status |
|---|---|
| **v1.0** | Compat shim retained, marked `#[deprecated]`. |
| **v1.x** | No further changes; the shim continues to work. |
| **v2.0** | `gitway-lib` removed entirely. |

There is no firm date for v2.0; expect the v1.x line to receive
patches and minor releases for the foreseeable future.

## Out of scope for v1.0

Three feature areas are explicitly deferred.  If you depend on
them, **stay on OpenSSH for those specific workflows** until the
referenced minor release.

| Feature | Status | Tracking |
|---|---|---|
| FIDO2 / `sk-ssh-*` hardware keys (M16) | Deferred to v1.1 | PRD §13 |
| Live `@cert-authority` validation during KEX (FR-61/62/63) | Deferred to v1.1 | russh upstream |
| Full `Match` block semantics in `ssh_config` | Deferred to v1.1 | PRD §12 Q1 |
| HTTP 429/503 retry semantics | Out of scope by construction | No HTTP layer in transport path |

## Where to ask for help

- **GitHub issues:** https://github.com/Spacecraft-Software/Gitway/issues
- **Anvil issues:** https://github.com/Spacecraft-Software/Anvil/issues (for
  library-layer questions about `anvil-ssh`)
- **Security disclosures:** see `SECURITY.md` at the repo root.

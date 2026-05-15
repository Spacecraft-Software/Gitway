# Gitway `ssh_config(5)` deviations from OpenSSH

This document lists every place where Gitway's `~/.ssh/config`
parsing or interpretation differs from OpenSSH's `ssh(1)`.  Most
deviations are deferred-to-v1.1 items; a small handful are
intentional design choices.

**Scope:** the `anvil_ssh::ssh_config` parser/resolver consumed by
`gitway` and `gitway-keygen` / `gitway-add`.

## Deferred to v1.1

### `Match` blocks (PRD §12 Q1)

OpenSSH evaluates `Match host`, `Match user`, `Match exec`, etc.,
to apply context-conditional configuration.  Gitway's parser
**recognizes** `Match` blocks (no syntax error) but **never
matches** any of them — `Match`-block directives have no effect on
the resolved configuration.

| Surface | Behavior |
|---|---|
| Parse | OK — `Match` is a known token, no error. |
| Match | Always false — `Match`-block directives are silently dropped. |
| `gitway config show` | The provenance list does not include `Match`-block lines. |

**Workaround:** use `Host` blocks with explicit hostname patterns
instead.  Example:

```text
# Instead of:
#   Match host *.internal.example exec "test -f /tmp/internal-mode"
#       IdentityFile ~/.ssh/id_internal
# Write:
Host *.internal.example
    IdentityFile ~/.ssh/id_internal
```

### Live `@cert-authority` host-key validation during KEX (FR-61, FR-62, FR-63)

Gitway parses `@cert-authority` lines in `~/.ssh/known_hosts` and
surfaces them in `gitway config show --json` for audit
purposes (FR-60).  However, **the SSH handshake never validates a
server-presented host certificate against the configured CA**
because russh's `Preferred::DEFAULT.key` set excludes the
`*-cert-v01@openssh.com` host-key algorithms.  KEX therefore never
asks for a certificate host-key, and `check_server_key` only sees
the underlying public key.

| FR | Status in v1.0 |
|---|---|
| FR-60 — parse `@cert-authority` lines | ✅ Done |
| FR-61 — validate server-presented host certificates against the CA during KEX | ⏳ Deferred to v1.1 — blocked on russh upstream cert-host-key support |
| FR-62 — emit a meaningful error when the server certificate is signed by a CA Gitway doesn't trust | ⏳ Deferred (depends on FR-61) |
| FR-63 — surface the verified-CA fingerprint in `gitway --test --json` output | ⏳ Deferred (depends on FR-61) |
| FR-64 — `@revoked` line as a policy-overriding blocklist | ✅ Done |

The deferral is tracked at the russh upstream issue (link to be
added once the upstream tracking issue lands).  When russh exposes
server certificates to `check_server_key`, FR-61/62/63 land in a
v1.1 minor release.

## Intentional design choices

### Algorithm denylist (FR-78)

Gitway maintains a hard denylist of algorithms (`anvil_ssh::algorithms::DENYLIST`)
that cannot be re-enabled even with `--kex +ssh-1.0` or
`KexAlgorithms +ssh-1.0` in `ssh_config`.  Currently denylisted:

- `ssh-dss` (DSA — too short, deprecated)
- `3des-cbc` (3DES — small block size, slow, deprecated)
- `arcfour`, `arcfour128`, `arcfour256` (RC4 — broken)
- `hmac-sha1-96` (truncated HMAC)
- `ssh-1.0` (the SSH-1 protocol — unsafe)

OpenSSH still accepts most of these (with warnings).  Gitway
refuses unconditionally and points at `gitway list-algorithms`
plus the external `ssh -W` tunneling workaround in the error
hint.

### `IdentityFile` redaction

By default, `gitway config show` redacts the `IdentityFile`
absolute path to `[REDACTED]` per NFR-20 to avoid leaking
home-directory paths into shell history / log shippers.  Pass
`--show-secrets` to override.  OpenSSH's `ssh -G` always shows the
full path.

### `HashKnownHosts` privacy threat model

OpenSSH's `HashKnownHosts yes` format hashes hostnames with HMAC-SHA1
+ a per-line salt.  Gitway inherits OpenSSH's threat model: the
hash is a privacy primitive that defends against casual file
inspection, not against an attacker who can run candidate hostnames
through HMAC-SHA1.  Hostnames have low entropy (a 6–7 character
domain is brute-forceable in seconds).

This is documented here, in `docs/security.md`, and in the
CHANGELOG.

## Compatibility tier

| Surface | Tier |
|---|---|
| `Host`, `HostName`, `Port`, `User`, `IdentityFile`, `IdentityAgent`, `CertificateFile` | ✅ Full compatibility |
| `IdentitiesOnly`, `StrictHostKeyChecking`, `UserKnownHostsFile` | ✅ Full compatibility |
| `ProxyCommand`, `ProxyJump`, `ProxyCommand=none` | ✅ Full compatibility (M13) |
| `KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms` (with `+/-/^/replace` syntax) | ✅ Full compatibility (M17) |
| `ConnectTimeout`, `ConnectionAttempts` | ✅ Full compatibility (M18) |
| `Include` directive | ✅ Full compatibility (M12) |
| `Match` blocks | 🟡 Parsed but never match (deferred to v1.1) |
| `@cert-authority` known_hosts lines | 🟡 Parsed + surfaced for audit; live validation deferred |
| `@revoked` known_hosts lines | ✅ Full compatibility (FR-64) |
| `HashKnownHosts yes` (HMAC-SHA1 hashed entries) | ✅ Full compatibility (M19) |

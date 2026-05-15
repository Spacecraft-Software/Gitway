# Gitway threat model and security posture

This document spells out what Gitway protects against, what it
does not, and the design choices that shape that posture.  It is a
companion to `SECURITY.md` (disclosure policy) at the repo root.

**Scope.**  This document covers the `gitway` binary, the
`gitway-keygen` and `gitway-add` companion shims, and the
`anvil-ssh` library that underpins them.  It does not cover
upstream dependencies (russh, ssh-key, aws-lc-rs, ed25519-dalek,
rsa) — each of those projects has its own security policy.

## Attacker models

### A1 — Active network attacker between client and Git host

**Capabilities.**  Can intercept, modify, or replay traffic
between the user's machine and `github.com` /
`gitlab.com` / `codeberg.org` / a self-hosted host.  Can present
arbitrary SSH host keys and certificates.

**Defenses.**

- **Embedded host-key fingerprints.**  GitHub, GitLab, and
  Codeberg fingerprints are pinned in `anvil_ssh::hostkey` at
  build time.  A man-in-the-middle that swaps the host key trips
  `check_server_key` and the connection aborts before
  authentication.
- **`@revoked` enforcement.**  Revoked fingerprints in
  `~/.config/gitway/known_hosts` are checked first, **before** the
  `StrictHostKeyChecking=no` bypass — no policy can override a
  revocation.
- **Algorithm denylist (FR-78).**  DSA, 3DES, RC4, hmac-sha1-96,
  and the SSH-1 protocol are refused unconditionally; an attacker
  cannot negotiate a downgrade to a broken cipher.
- **`aws-lc-rs` crypto backend.**  FIPS-quality crypto
  primitives; constant-time comparisons throughout.

**Residual risk.**  An attacker who can rotate the legitimate host
key faster than Gitway's release cycle can land them in a window
where Gitway rejects valid keys.  Mitigation: see the SSH
fingerprint rotation procedure in `CLAUDE.md`.

### A2 — Local attacker with read access to the user's filesystem

**Capabilities.**  Can read `~/.ssh/`, the agent socket, the
`~/.config/gitway/` directory, and shell history files.

**Defenses.**

- **`#![forbid(unsafe_code)]` everywhere.**  Project-owned crates
  refuse to compile if any `unsafe` block is added — kills entire
  classes of memory-safety vulnerabilities.
- **Passphrase zeroization.**  Every `String` holding a passphrase
  is wrapped in `Zeroizing<String>`; bytes are overwritten before
  deallocation.  See the security invariants in `CLAUDE.md` for
  the full list (`from_utf8_lossy` forbidden on passphrase data;
  raw `SSH_ASKPASS` stdout zeroized; etc.).
- **Path redaction.**  `gitway config show` redacts
  `IdentityFile` paths to `[REDACTED]` per NFR-20 to keep
  home-directory paths out of shell history and log shippers.
- **`SSH_ASKPASS` validation.**  `SSH_ASKPASS` must be an
  absolute path; world-writable askpass programs are rejected on
  Unix.

**Residual risk.**  Standard local-attacker-can-read-files
caveats.  A local attacker with read access to the user's private
key file can use it; a hardware-backed key (FIDO2) is the right
defense, and is deferred to v1.1.

### A3 — Compromised SSH agent

**Capabilities.**  An agent process under attacker control on the
agent socket (Unix `$SSH_AUTH_SOCK` or Windows
`\\.\pipe\openssh-ssh-agent`).

**Defenses.**

- **Confirm-on-use (`ssh-add -c`).**  Identities added with
  `gitway agent add --confirm` require explicit user
  confirmation per signature; an attacker driving the agent
  cannot silently sign with a confirm-required key.
- **Lock/unlock with a passphrase.**  `gitway agent lock` /
  `unlock` gate access to all identities behind a separate
  passphrase.

**Residual risk.**  An attacker who controls the agent socket
**and** has stolen the passphrase or trickedthe user into typing
yes at every confirm prompt can sign on the user's behalf.
Mitigation: hardware-backed keys (FIDO2 / `sk-ssh-*`, deferred
to v1.1).

### A4 — Hostile `~/.ssh/config` content

**Capabilities.**  An attacker who can modify `~/.ssh/config` (or
something it `Include`s) before Gitway runs.

**Defenses.**

- **`ProxyCommand=none` sentinel honored** (FR-59) — administrators
  can disable inherited `ProxyCommand` settings.
- **Independent host-key verification at every jump-host hop**
  (NFR-17).  A compromised intermediate hop cannot silently
  intercept traffic by forwarding to a different terminal host.

**Residual risk.**  Standard config-injection caveats.  A user
who runs Gitway with a hostile `~/.ssh/config` will fetch via
whatever transport that file specifies.

## Known residual risks (accepted for v1.0)

### RUSTSEC-2023-0071 — Marvin Attack on the `rsa` crate

**What it is.**  The RustCrypto `rsa` crate's modular-exponentiation
path leaks timing information that can, in principle, be used to
recover an RSA private key by an attacker who can observe many
signature timings precisely enough.  Both `rsa = "0.9"` (transitive
via `ssh-key`) and `rsa = "0.10.0-rc"` (transitive via russh) are
affected.  No patched release exists yet upstream
([RustCrypto/RSA #626](https://github.com/RustCrypto/RSA/issues/626)).

**Why we ship anyway.**

1. **Use site is local.**  Gitway's transport crypto goes through
   russh's `aws-lc-rs` backend, which is constant-time.  The `rsa`
   crate is only on the keygen and SSHSIG-signing paths, both of
   which are local operations.
2. **SSH auth signatures are infrequent.**  At most one or two
   per session, far below the sample count Marvin-style timing
   recovery needs.
3. **Network jitter dominates.**  The discriminator the attack
   needs (sub-microsecond differences in modular operations) is
   well below SSH connection RTT noise.
4. **The default Gitway key type is Ed25519**, which is not
   affected by this advisory.

**What this means for users with RSA keys.**  If you authenticate
to a Git host with an RSA private key that you generate or sign
with via `gitway keygen` / `gitway sign`, and you regularly do so
on a machine where an attacker can observe sub-microsecond timing
of those local operations, prefer Ed25519 until upstream ships a
patched release.

**Tracking.**  Recorded in `deny.toml` `advisories.ignore`; reviewed
at every release.  Will be lifted as soon as RustCrypto/RSA cuts a
patched version.

## Defenses that intentionally do not exist (yet)

| Gap | Why it's not in v1.0 | Tracked at |
|---|---|---|
| FIDO2 / hardware-backed keys (M16) | Vendor fragmentation; needs hardware-test matrix; deferred to v1.1 | PRD §13 |
| Live `@cert-authority` validation during KEX (FR-61/62/63) | russh upstream lacks cert-host-key support | russh upstream tracking issue |
| Full `Match` block semantics | Parser-only support shipped in v1.0; eval deferred | PRD §12 Q1 |

If your threat model requires any of these, **stay on OpenSSH**
for those specific workflows until the referenced minor release.

## What `HashKnownHosts` does and does not protect

OpenSSH's `HashKnownHosts yes` format hashes hostnames with HMAC-SHA1
+ a per-line salt.  The threat model (which Gitway inherits via
M19) is:

- **Defends against:** casual file inspection.  Someone reading a
  hashed `known_hosts` file does not immediately see the list of
  hosts the user has connected to.
- **Does not defend against:** brute-force.  Hostnames have low
  entropy.  An attacker with a candidate list (e.g. all common
  GHE deployments at a company) can run each through HMAC-SHA1
  with the file's salts in seconds.

This is documented here, in `docs/ssh_config-deviations.md`, and
in the v1.0 CHANGELOG.

## Reporting vulnerabilities

See `SECURITY.md` at the repo root.  Use GitHub Security Advisories
for confidential disclosure.  Do **not** open public issues for
suspected vulnerabilities.

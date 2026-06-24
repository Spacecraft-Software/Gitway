<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Biometric (fingerprint) unlock

Gitway can unlock a passphrase-protected SSH key with your computer's
fingerprint reader instead of a typed passphrase. This is an **opt-in**
convenience: the official binaries are built with the `biometric` feature; a
`cargo install gitway` adds it with `--features biometric`.

## How it works

A fingerprint cannot decrypt a key the way a passphrase can — biometrics only
*gate access to a stored secret*. So Gitway stores the key's passphrase in your
operating system's secure keystore and releases it after a local biometric
check:

1. **Enroll once:** `gitway biometric enroll ~/.ssh/id_ed25519` prompts for the
   passphrase, verifies it decrypts the key, and stores it in the keystore.
2. **Unlock later:** `gitway-add ~/.ssh/id_ed25519` (or `gitway agent add`)
   asks the OS to release the passphrase; the OS raises a fingerprint prompt,
   and on success Gitway decrypts the key and loads it into the agent — no
   typing.

Biometric unlock is **purely additive**. On the normal Git transport path, if a
key is not enrolled, a backend is unavailable, or you cancel the prompt, Gitway
silently falls back to the usual passphrase prompt — it never blocks a push.

## Security-binding strength is NOT the same on every platform

This is the most important thing to understand. Run `gitway biometric status`
to see the active tier.

| Platform | Tier | What the fingerprint actually protects |
|----------|------|----------------------------------------|
| **macOS** | `hardware-bound` | The Secure Enclave releases the secret only on a biometric/passcode match. Strong. |
| **Windows** | `dpapi-consent` | The secret is DPAPI-encrypted at rest; a Windows Hello consent prompt gates the read but is **not** cryptographically bound to it. |
| **Linux** | `advisory` ⚠️ **experimental** | `fprintd` verifies your fingerprint, but the passphrase is protected by your **login keyring** (gnome-keyring / KWallet), **not** by the fingerprint. |

### Linux is a convenience gate, not a security boundary

On Linux the fingerprint check is **advisory**. The passphrase lives in your
Secret Service keyring, which is unlocked by your login session — not by the
fingerprint. A local attacker who already has your unlocked session can read the
keyring directly (e.g. with `secret-tool`) and **bypass the fingerprint check
entirely**. Treat Linux biometric unlock as *convenience*, the same trust level
as an unlocked keyring — not as an additional security boundary. Gitway prints
this warning once when you enroll on Linux.

## Commands

```sh
gitway biometric enroll [FILE...]   # store the passphrase behind a biometric check
gitway biometric forget [FILE...]   # remove enrollment (or --all)
gitway biometric list               # list enrolled keys
gitway biometric status             # availability + binding tier (--json supported)
```

Flags on the load path:

```sh
gitway-add --biometric ~/.ssh/id_ed25519     # enroll-then-load
gitway-add --no-biometric ~/.ssh/id_ed25519  # force a typed passphrase
gitway agent add --biometric ~/.ssh/id_ed25519
```

Without a flag, loading is **auto**: biometric when the key is enrolled and a
backend is available, otherwise a passphrase prompt.

## Requirements

- **Linux:** a working `fprintd` (`fprintd-enroll` to register a finger) and a
  Secret Service keyring daemon (gnome-keyring or KWallet) on the session bus.
  In headless / container / CI environments without these, biometric is simply
  unavailable and Gitway falls back to the passphrase prompt.
- **macOS:** a Touch ID–capable Mac (falls back to the device passcode).
- **Windows:** Windows Hello configured for the user.

## Exit codes

See [`exit-codes.md`](exit-codes.md). Biometric-specific mappings: a cancelled
or non-matching prompt is `73` (user declined); biometric explicitly requested
but unavailable is `78`; `forget` on a key that is not enrolled is `3`.

## Stale enrollment

If you change a key's passphrase (`gitway keygen change-passphrase`), the stored
secret no longer decrypts it. On the next auto load Gitway detects this, removes
the stale enrollment, and falls back to a passphrase prompt — re-enroll with
`gitway biometric enroll` to restore fingerprint unlock.

# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in Gitway,
please **do not open a public GitHub issue**.  Instead, use one of
the confidential channels below.

### Preferred — GitHub Security Advisories

Visit https://github.com/Spacecraft-Software/Gitway/security/advisories and
click **Report a vulnerability**.  This opens a private issue
visible only to the project maintainers.

For library-layer issues that originate in the `anvil-ssh` crate
(transport, host-key handling, agent, signing primitives), please
file at https://github.com/Spacecraft-Software/Anvil/security/advisories
instead.  When in doubt, file with Gitway and we'll route it.

### Email fallback

If GitHub Security Advisories are unavailable, email
**[Mohamed.Hammad@SpacecraftSoftware.org](mailto:Mohamed.Hammad@SpacecraftSoftware.org)** with:

- A clear description of the vulnerability
- Reproduction steps (a minimal proof-of-concept if possible)
- The affected version (output of `gitway --version`)
- Your preferred contact for follow-up

We acknowledge reports within **3 business days** and aim to ship
a fix within **30 days** for confirmed issues.

## Disclosure timeline

Our default disclosure window is **90 days from the initial
report**.  We will:

1. Acknowledge the report within 3 business days.
2. Confirm or dispute the issue within 14 days.
3. If confirmed: develop, test, and ship a fix within 30 days
   (or coordinate a longer timeline with the reporter for complex
   issues).
4. Publish a coordinated disclosure (CVE if appropriate, GitHub
   Security Advisory, CHANGELOG entry) on or before day 90.

If we are unresponsive or you disagree with our handling, you may
disclose publicly after the 90-day window.

## Scope

In scope:

- The `gitway`, `gitway-keygen`, `gitway-add` binaries
- The `gitway-lib` shim (deprecated, but still ships in v1.x)
- The `anvil-ssh` library (file in the Anvil repo when the issue
  originates there)
- Build tooling, CI workflows, and packaging artifacts that ship
  binaries

Out of scope:

- Upstream dependencies (russh, ssh-key, aws-lc-rs, etc.) — please
  report those upstream
- Issues that require an attacker who already has root / admin on
  the user's machine
- Cosmetic issues, typos, missing-feature reports — those are
  regular GitHub issues

## Threat model

See `docs/security.md` for the in-depth threat model.  TL;DR:
Gitway defends against active network attackers (via embedded
host-key fingerprints, the algorithm denylist, and `@revoked`
enforcement) and against memory-safety classes of vulnerability
(via `#![forbid(unsafe_code)]` everywhere).  It does not defend
against an attacker who has read access to the user's private key
file — for that, use a hardware-backed key (deferred to v1.1).

## Acknowledgments

We credit reporters in the CHANGELOG entry for each fixed issue
unless the reporter requests otherwise.

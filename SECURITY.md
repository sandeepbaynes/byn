# Security Policy

byn is a security tool, so please report suspected vulnerabilities
**privately** — do not open a public issue or pull request for one.

## Reporting a vulnerability

- **Preferred:** GitHub → **Security → Report a vulnerability** (a private
  advisory): <https://github.com/sandeepbaynes/byn/security/advisories/new>
  *(requires "Private vulnerability reporting" enabled on the repo).*
- **Fallback:** email **sandeep.baynes@gmail.com** with `byn security` in the
  subject.

Please include the affected version (`byn version`), a description, and a
minimal reproduction. **Never include real secrets, vault contents, or
credentials** in a report — redact values (names are fine).

## Scope

byn defends the **development-time** workflow; see
[`docs/security.md`](docs/security.md) for the full threat model and its honest
ceilings.

**In scope:** vault-key handling and wrapping, the unlock/lock and passkey
(WebAuthn PRF) paths, the HMAC-chained audit log, IPC peer-UID enforcement,
`.byn` trust, and any leak of secret **values** into argv, environment, disk, or
logs.

**Out of scope (documented limitations, not vulnerabilities):** a fully
compromised daemon, or a same-UID local attacker who can `ptrace` the daemon or
drive the browser — see the "owned by you, operated by many" section of the
threat model. Cloud sync, shims, and FUSE are not yet shipped.

## Response

This is currently a solo-maintained project. I aim to acknowledge reports within
a few days and will coordinate a fix and a disclosure timeline with you. There
is no bounty program at this time.

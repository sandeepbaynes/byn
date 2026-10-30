# Field notes

A mini blog inside the byn docs: how secrets actually leak in agentic
development, what byn covers **now**, where it can't, and what's coming.
**Every field note is reviewed and re-stamped at each byn release** — the
coverage line at the top of each page tells you which version its claims
were verified against.

---

## Field notes

- **[The AWS credentials file that cost me my account](aws-credential-file-takeover.md)**
  — from the author: a plaintext `~/.aws/credentials` on a VM, an
  account takeover, and the fast-agents-vs-restrictive-IAM tension that
  byn was built to resolve.
- **[How agents and bots leak your secrets](how-agents-leak-secrets.md)**
  — the seven leak vectors, one by one: byn today / where byn can't
  protect / what's coming. Ends with the agentic-development best
  practices checklist.
- **[Real-world incidents byn is built for](real-world-incidents.md)**
  — verified, linked incidents (s1ngularity, Shai-Hulud, the Amazon Q
  wiper prompt, secret-sprawl numbers, …) with honest verdicts —
  including where another credential manager would have helped too, and
  where byn would not have helped at all.
- **[byn vs the other tools, honestly](tool-comparison.md)**
  — strengths and weaknesses of `.env`, direnv, mise, Doppler,
  Infisical, Vault, 1Password CLI, aws-vault — and byn's own
  weaknesses, listed just as bluntly. Capability matrix included.
- **[Why byn doesn't use containers](../why-not-containers.md)**
  — design rationale: a container's boundary points the wrong way for
  this threat; sandbox the agent, not the secret.

### 2026 incident notes

Single-incident write-ups, newest first. Each uses the same verdict
rules as the pages above, and each says where byn would not have helped.

- **[The trojaned Claude Code extension, and what an editor extension can reach](claude-code-extension-2-1-313.md)**
  — on 29 October 2026 a tampered VS Code extension, served from Open
  VSX and Cursor, planted an SSH backdoor and told its operator which
  credential variables were on the machine. Why that list is empty
  under byn, what an attacker's shell can and cannot get at afterwards,
  and the parts byn does not cover: `~/.ssh` and the backdoor itself.
- **[October's npm credential stealers, and what they would have found under byn](npm-october-2026-harvesters.md)**
  — SubQuery, Tensorlake and the testmetest worm in one month, the one
  trap byn users must know about (never pin `npm install` with secrets
  in scope), and why the Node.js Brotli bug is a production problem byn
  cannot claim.
- **[PHP in 2026: PHP2Shell, a Composer plugin that stole keys, and a token in the CI log](php-2026-php2shell-composer.md)**
  — byn is no help against the server-side PHP bug, a real help against
  the Composer plugin that ran on developer machines, and no help for
  the CI log leak. The Composer `auth.json` caveat is spelled out.
- **[Oracle Health: twenty million records behind one stolen credential](oracle-health-one-credential.md)**
  — the largest 2026 example of the pattern byn targets, and a breach
  byn would not have prevented. The note explains why it is here anyway.

---

## Ground rules for these pages

- **Accuracy over reassurance.** Verdicts say ✓ / ◐ / ✗, and ✗ stays on
  the page. If a claim doesn't match the shipped behavior of your
  version, that's a docs bug — open an issue.
- **Sources are verified.** Incident links are checked when added; no
  recollection-based citations.
- **Roadmap claims are labeled.** "Next release" and "planned" mean
  exactly what the [Security model](../security.md) says they mean.

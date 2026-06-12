# Field notes

A mini blog inside the byn docs: how secrets actually leak in agentic
development, what byn covers **now**, where it can't, and what's coming.
**Every field note is reviewed and re-stamped at each byn release** — the
coverage line at the top of each page tells you which version its claims
were verified against.

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

## Ground rules for these pages

- **Accuracy over reassurance.** Verdicts say ✓ / ◐ / ✗, and ✗ stays on
  the page. If a claim doesn't match the shipped behavior of your
  version, that's a docs bug — open an issue.
- **Sources are verified.** Incident links are checked when added; no
  recollection-based citations.
- **Roadmap claims are labeled.** "Next release" and "planned" mean
  exactly what the [Security model](../security.md) says they mean.

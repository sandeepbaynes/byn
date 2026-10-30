# October's npm credential stealers, and what they would have found under byn

*Field note · coverage: v0.9.2 · incidents: 5 to 28 October 2026 · written 30 October 2026*

Three separate operations put credential-stealing packages on npm in
October 2026. Each one ran when a developer installed a package, read
whatever credentials it could find on the machine, and used them to
reach the next victim. In the same month the Node.js project fixed a bug
in its Brotli decoder that allows remote code execution. This note goes
through each of them and asks one question: if the secrets had been in
byn, what would the payload have found?

The answer is different for each, and in one case there is a trap that
byn users need to know about, so the verdicts are not uniform.

| Incident | What it read | byn v0.9.2 |
|---|---|---|
| `@subql/common` 5.8.3, 5 October | `.npmrc`, `.env`, AWS credentials, SSH keys, kubeconfig, `.claude.json`, the whole process environment, the output of `gh auth token`, CI runner memory, AWS Secrets Manager | ✓ for credentials held in the vault. ◐ when your application imports the package under `byn exec`. ✗ for SSH keys and CI. |
| `tensorlake` 0.5.144, 8 October | More than sixty named environment variables, `~/.aws`, `~/.kube`, `~/.ssh`, `~/.vault-token`, `~/.docker`, cloud CLI caches, wallets, browser data | ✓ for environment and cloud credentials. ✗ for SSH keys, wallets and browsers. |
| The testmetest worm, reported by JFrog on 26 October | GitHub and npm credentials; it also poisons repositories and CI configuration | ◐ |
| Node2Shell, CVE-2026-111497, fixed 21 October | Anything in the memory of a Node process that decompresses attacker-supplied Brotli data | ✗ on servers. ◐ for a development process. |

Verdict key: ✓ prevented or defanged · ◐ materially reduced or detected
· ✗ byn would not have helped.

---

## The three stealers

### SubQuery: published through the project's own trusted publisher

A malicious `@subql/common` 5.8.3 appeared on npm at 11:56 UTC on 5
October. [StepSecurity's
write-up](https://www.stepsecurity.io/blog/subql-ecosystem-compromised)
traces it to two commits that rewrote the project's release workflow.
The job still built the real repository, but a new step then downloaded
an archive from `ci-artifacts.dev`, deleted the freshly built
`packages/common`, unpacked the download in its place, and published it.
Nothing checked the archive's hash or signature. Anyone looking at the
package saw the project's legitimate publishing identity.

The payload runs in two situations. It runs from a `postinstall` hook,
and it runs again whenever the package is imported, so turning off
install scripts does not help. StepSecurity is careful to describe what
follows as capabilities found in the code, not as proof of theft from any
particular machine. The code tries to read `.npmrc`, `.env`, AWS
credentials, SSH keys, kubeconfig files, cloud CLI caches, wallet paths
and AI tool configuration such as `.claude.json`. It copies the entire
`process.env` object and runs `gh auth token`. On Linux GitHub Actions
runners it uses `sudo python3` to read the runner worker's memory through
`/proc` and pick out values flagged as secrets. With cloud credentials in
hand it enumerates AWS Secrets Manager and Parameter Store across
seventeen regions, Kubernetes service-account secrets and Vault. And if
it finds a usable GitHub token, it pushes a workflow named "Run Copilot"
to up to five repositories at a time that serialises every repository
secret into a build artifact.

What it collects is compressed, encrypted and posted back to
`ci-artifacts.dev`. There is also a check-in channel that can run shell
commands and attach a terminal. The payload sets
`NODE_TLS_REJECT_UNAUTHORIZED=0` for good measure.

### Tensorlake: a maintainer's identity and a direct file upload

[Aikido](https://www.aikido.dev/blog/tensorlake-npm-package-compromised)
reports that on 7 October someone made commits to the `tensorlake`
repository "under the identity of a maintainer," introduced the malware
"via direct file upload," and after roughly twenty hours got the
poisoned 0.5.144 published on 8 October. The package's `preinstall`
script runs `node lib/setup.mjs`, which drops the Bun runtime and uses it
to execute an obfuscated variant of the Shai-Hulud worm.

Its shopping list is long. It looks for more than sixty environment
variables, including `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`VAULT_TOKEN` and `KUBECONFIG`. It reads `~/.aws/credentials`,
`~/.aws/config`, `~/.kube/config`, `~/.ssh`, `/etc/ssh`,
`~/.vault-token`, `~/.docker`, the gcloud and Azure credential caches,
`~/.config/github-copilot`, cryptocurrency wallets and browser extension
stores. Its command server is resolved through an Ethereum smart
contract, and it carries a dead-man's switch that wipes the host if the
GitHub token embedded in it is revoked. Aikido's advice is to treat an
infected machine as fully compromised and rotate everything on it.

### testmetest: 42 hijacked repositories and a native addon in postinstall

[JFrog's report of 26
October](https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/)
inventories 25 package names and 82 published versions, fifteen of the
packages malicious, plus 42 armed GitHub repositories belonging to eleven
legitimate owners. The worm "stole GitHub and npm credentials that could
provide access to third-party repositories." A hidden publisher script
was written to run inside GitHub Actions and "use npm tokens or trusted
publishing to produce further malicious testmetest releases," exchanging
a GitHub OIDC token for an npm publish token. Newer builds hide the
loader inside a native `.node` addon called from a `postinstall` script
whose `try/catch` "swallows every error," and they quietly exit if they
notice a CI environment, a container, a small virtual machine or a
debugger. JFrog's conclusion: "Treat installation of a full-worm version
as a host compromise."

### What they have in common

Three operators, one method. Get code running on a developer's machine
through the package manager. Read the credentials that are sitting there,
in files at well-known paths and in the environment the install
inherited. Use those credentials, the npm token, the GitHub token, the
cloud keys, to publish the next poisoned version and begin again. Every
link in that chain is a credential that any process running as the
developer could read.

---

## What byn changes

### The files

Under byn there is no `.env`. The repository carries a `.byn` manifest of
names that is safe to commit, and the values sit encrypted in the vault,
each under its own key. There is no `~/.aws/credentials` either, if the
access key and secret live in the vault and you run `byn exec -- aws`.

The same is true of the token files these payloads enumerate, as long as
the token is held as a variable rather than written to disk. The GitHub
CLI reads `GH_TOKEN` from the environment, so outside a `byn exec` there
is nothing for `gh auth token` to print. npm expands environment
variables in `.npmrc`, so a line like
`//registry.npmjs.org/:_authToken=${NPM_TOKEN}` leaves a reference in the
file and nothing else. Tensorlake's `~/.vault-token` and SubQuery's
seventeen-region sweep of Secrets Manager both need a credential to start
from, and with none lying around they have nothing to run as.

What a sweep does find is the vault file itself. Entry names are stored
in plaintext, deliberately, so that they can be listed while the vault is
locked. Values are sealed. A copy can be attacked offline against the
master passphrase, which is the [named
weakness](../security.md#known-weaknesses--how-to-protect-yourself) a
long passphrase and full-disk encryption exist for.

### The environment, and the trap

`npm install` runs in your terminal and inherits your shell's
environment. Under byn that environment holds no secret values, because
`byn exec` injects only into the process it replaces itself with. So
SubQuery's copy of `process.env` and Tensorlake's list of sixty names
would have returned `PATH`, `HOME`, `TERM` and `BYN_PROJECT`.

Here is the trap. If you run `byn exec -- npm install`, the injected
variables go to `npm`, and the lifecycle scripts of every package being
installed are `npm`'s children. If you pin `npm install`, or `yarn`, or
`pnpm install`, in a `.byn` whose `[exec] env` is broad, you have built
exactly what these payloads hope for: a trusted, password-free command
that runs arbitrary third-party code with your cloud keys in its
environment. Do not pin package manager installs with secrets in scope.
Install with nothing injected, and run the application, not the
installer, under `byn exec`, with the narrowest `[exec] env` it needs.
byn's default helps: a `.byn` with no `[exec] actions` pins nothing, so
every exec prompts. Keeping the list narrow is still your job.

### Import-time execution

SubQuery's payload also fires when your application `require`s the
package. If you start that application with `byn exec -- node server.js`,
the payload runs inside a process that legitimately holds its injected
variables, and reading `process.env` gives them up. byn cannot stop a
process from reading its own environment. No injection tool can.

What byn changes is how much the process holds and what gets recorded.
The process has the `[exec] env` allowlist for that one command, not
every secret in a `.env`, not `~/.aws/credentials`, not the kubeconfig,
not the Vault token. The audit log records the exec with the authorising
`.byn`, the exact command line, the caller's process chain, and which
entries were injected, so the question "what did the compromised service
have access to?" has a short answer instead of "everything on the
laptop." With privilege separation, the child runs as `_byn-exec`, and
the payload's other moves, such as reading sibling processes, the daemon
socket or session files, need root.

### The CI half

Runner memory on GitHub Actions, the OIDC token exchange, the pushed
"Run Copilot" workflow: none of that is on your machine, and byn's domain
ends at your machine. These campaigns go after CI because CI is where
long-lived publish credentials and repository secrets sit together, and
the fixes there are short-lived scoped tokens, environment protection
rules and immutable releases. What the October wave does show is that
the chain starts on a workstation: the Tensorlake maintainer identity,
the GitHub tokens behind testmetest's hijacked repositories, and the
hijacked contributor account in the OVHcloud CLI incident the same month.
The workstation is where byn stands.

---

## Node2Shell, which is really about production

On 21 October the Node.js project [released security
updates](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
22.23.4, 24.22.1 and 26.12.1 fixing ten CVEs. The one that matters most
is CVE-2026-111497, described by the project as "Node.js Brotli decoder
out-of-bounds write permits remote code execution." In its words, "An
attacker who can supply Brotli data that an application decompresses
with `node:zlib` can corrupt process memory." [Akamai's
analysis](https://www.akamai.com/blog/security-research/inside-node2shell-closer-look-cve-2026-111497)
lists the exposed paths as `node:zlib`, the built-in `fetch()`, and
request bodies in Express 5 and body-parser 2, with outcomes ranging from
a crash to disclosure of process memory to code execution. No
authentication is needed. Google scores it 9.2 on CVSS v4; Node.js rates
it High. End-of-life lines, 25.x, 23.x, 20.x and earlier, get no fix.
[Rescana](https://www.rescana.com/post/nodejs-cve-2026-111497-node2shell-brotli-rce-october-2026)
reported on 27 October that CISA had added it to the Known Exploited
Vulnerabilities catalogue; the Node.js advisory itself says nothing
about exploitation either way.

The same release updated the bundled certificate store for the eMudhra
intermediate CA compromise of 17 October, which is also why byn v0.9.2
is built with Go 1.27.3 (see the [release
notes](../releases.md#v092)).

byn's verdict here is ✗ for the server and ◐ for the dev box. A public
Node service compromised through Brotli is a production incident
somewhere byn does not run. If the vulnerable process is a dev server on
your laptop started with `byn exec`, an attacker who gets code execution
inside it reads its environment, which is the allowlist for that command
rather than your whole credential estate, and the exec is in the audit
log. That is a smaller exposure, not none. Patch Node.

---

## Would another credential manager have helped?

For the files and the shell environment, yes. `op run`, `doppler run`,
Infisical and aws-vault all take values out of dotfiles and inject them
at run time, and each would have emptied most of these target lists.
Where they differ from byn is the part this month's campaigns leaned on
hardest, the install step. A cloud vault's CLI, once authenticated, is
available to every process the user runs, including the lifecycle
scripts of `npm install`. byn's exec is per command and per `.byn`, with
a pinlist that defaults to empty, so there is no standing grant for a
`postinstall` script to draw on. None of those tools writes a per-access
audit line on the developer machine. The full comparison, including
byn's own weaknesses, is in [byn vs the other
tools](tool-comparison.md).

---

## What to do now

Check your lockfiles for `@subql/common@5.8.3`, `tensorlake@0.5.144`,
and the testmetest packages JFrog lists. If any of them was installed,
treat the host as compromised and rotate npm, GitHub, cloud, SSH,
Kubernetes and Vault credentials from a clean machine.

Upgrade Node to 22.23.4, 24.22.1 or 26.12.1, and rebuild container
images. The official `node` images were rebuilt on 21 October, so
anything built earlier still carries the old runtime.

Finish the byn migration. Import, confirm with `byn list`, then delete
`.env`, `~/.aws/credentials` and any token in `.npmrc`. A forgotten
`.env.backup` is exactly what these payloads are written to find.

Never pin installs. Keep `npm install`, `yarn` and `pnpm` out of
`[exec] actions`, and install with no secrets in scope. Run the
application under byn, not the package manager.

Keep `[exec] env` to what each command needs, keep the idle timeout
short, and provision privilege separation with `sudo byn setup`.

And read `byn audit tail` after any dependency change you did not
expect. Detection is the half of the model that is entirely in your
hands.

---

## Sources

- StepSecurity, [SubQuery ecosystem compromised: `@subql/common@5.8.3`](https://www.stepsecurity.io/blog/subql-ecosystem-compromised), 5 October 2026.
- Aikido, [tensorlake NPM package compromised with Shai Hulud worm](https://www.aikido.dev/blog/tensorlake-npm-package-compromised), 8 October 2026.
- JFrog Security Research, [Beyond testmetest: Native Addon Camouflage and 42 Armed GitHub Repositories](https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/), 26 October 2026.
- Node.js, [October 2026 Security Releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), 21 October 2026.
- Akamai, [Inside Node2Shell: A Closer Look at CVE-2026-111497](https://www.akamai.com/blog/security-research/inside-node2shell-closer-look-cve-2026-111497), 26 October 2026.
- Rescana, [Node2Shell added to CISA KEV](https://www.rescana.com/post/nodejs-cve-2026-111497-node2shell-brotli-rce-october-2026), 27 October 2026.

*Sources verified 30 October 2026. byn behaviour checked against the
v0.9.2 source and [the security model](../security.md). Reviewed and
re-stamped at each release.*

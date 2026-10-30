# PHP in 2026: PHP2Shell, a Composer plugin that stole keys, and a token in the CI log

*Field note · coverage: v0.9.2 · incidents: April to October 2026 · written 30 October 2026*

Three incidents touched the PHP ecosystem this year, and each exposed
credentials in a different place. PHP2Shell, in October, exposes whatever
is in the memory of a web server's PHP worker. The `intercom/intercom-php`
Composer plugin, in April, read credentials off the machine of whoever
ran `composer install`. And in May, a Composer bug printed GitHub tokens
into CI logs.

byn is a development-time vault, so its relevance to these three is very
uneven. The verdicts below reflect that, and the first one, for the bug
everyone is patching this week, is a plain no.

| Incident | Where the secret was exposed | byn v0.9.2 |
|---|---|---|
| PHP2Shell, CVE-2026-109618 and CVE-2026-109619, 21 October | The memory of a PHP worker on a server | ✗ on servers. ◐ on a developer machine. |
| `intercom/intercom-php` 5.0.2 Composer plugin, 30 April | The files and environment of the developer running `composer install` | ✓ for environment and cloud credentials. ✗ for SSH keys. |
| Composer token disclosure, CVE-2026-45793, 13 May | GitHub Actions job logs | ✗. Not byn's domain, though there is a lesson in it. |

Verdict key: ✓ prevented or defanged · ◐ materially reduced or detected
· ✗ byn would not have helped.

---

## PHP2Shell: unauthenticated code execution as the web server

On 21 October 2026 PHP released 8.5.12, 8.4.27, 8.3.36 and 8.2.35 to fix
two critical bugs. PHP's own advisory for
[CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
titled "RCE via OOM corruption," explains that PHP uses `longjmp()` to
bail out when it runs out of memory, and that if an allocation fails
while request memory is only partly initialised, the shutdown path can
read or branch on invalid state. The advisory's summary of the result:
"The confirmed impact is unauthenticated remote code execution as the
web worker account." CVE-2026-109619 is the companion bug, in which
request-owned global state goes stale and is reused by a later request
on the same worker. Both score 9.2 on CVSS v4. The release notes say
there are no complete mitigations and that updating is the only safe
choice.

[Sophos's advisory](https://www.sophos.com/en-us/security-advisories/sophos-sa-20261021-php2shell)
fills in the operational picture. The bugs became public on 20 October,
ahead of the coordinated disclosure date. Apache `mod_php` is the
highest-risk deployment because CVE-2026-109618 can be triggered "by an
unauthenticated request before any application code runs." PHP-FPM,
php-cgi, FrankenPHP and LiteSpeed are affected too. Amazon Threat
Intelligence reported an exploitation attempt on 17 October, before the
bugs were public, and other vendors have reported more since. PHP 8.1
and earlier are end of life; source-only backports exist for 7.4 through
8.1. The interim settings PHP suggests, `memory_limit=-1`,
`session.upload_progress.enabled=0`, and on 8.5
`fatal_error_backtraces=0`, reduce exposure but do not fix anything.

### What byn would have done on the server

Nothing, and it is better to say that plainly. byn runs on a developer's
machine. An attacker who gets code execution as `www-data` on a public
PHP server is on a box byn is not, reading a process byn did not start.
What is exposed is whatever that worker holds: the database password,
the API keys, the application key. In PHP those almost always come from
a `.env` file, loaded by `vlucas/phpdotenv` or `symfony/dotenv` into
`$_ENV`, `getenv()` and the process environment. Patch PHP. If your logs
show exploitation (Sophos suggests reviewing from 1 August for
unexpected multipart POSTs, `PHP_SESSION_UPLOAD_PROGRESS` requests,
memory-exhaustion spikes and new PHP files in web roots), rotate what
the worker could reach.

### On a developer machine

Where PHP2Shell does touch byn's territory is the Laravel or Symfony
application a developer runs locally with real credentials in `.env`,
which is the same file the Composer plugin below goes looking for. With
those values in byn and the dev server started as
`byn exec -- php artisan serve`, two things change. There is no `.env`
left for anything else on the machine to read. And an attacker who
exploits the local worker reads that process's environment, which is
the `[exec] env` allowlist for that command rather than the whole file,
with the exec recorded in the audit log along with the command line and
the calling process. byn cannot stop a process from reading its own
environment. It limits which process holds which secret, and it writes
down the handout. That is a smaller exposure, not a closed one.

---

## The Composer plugin that ran as you

On 30 April 2026 the group behind the "Mini Shai-Hulud" campaign
overwrote the existing 5.0.2 release of `intercom/intercom-php` on
Packagist with code that turns the package into a Composer plugin. They
compromised `intercom-client` 7.0.4 on npm the same day; the two
packages see about 400,000 downloads a week between them, according to
[Semgrep](https://semgrep.dev/blog/2026/malicious-intercom-php-package-spreads-mini-shai-hulud-attack-to-packagist-via-composer-plugin/).

Composer plugins run during `composer install`. This one downloaded the
Bun runtime and used it to run the campaign's obfuscated stealer, which,
in Semgrep's description, "steals GitHub tokens, SSH keys, cloud provider
credentials, and environment variables," encrypts what it finds, and
sends it to `zero.masscan.cloud`. The list of indicators is telling.
Alongside `src/composerPlugin.php` it includes `.claude/settings.json`,
`.claude/setup.mjs`, `.vscode/tasks.json` and `.vscode/setup.mjs`, which
are files that make an editor or a coding agent run the payload again
the next time the project is opened. Semgrep's point about how it
spread is worth repeating: replication "isn't a feature of the attack,"
it is "a feature of how Composer resolves dependencies." Any project
with the package anywhere in its dependency tree picked it up.

### What byn changes

`composer install` is code you did not write, running as you, in your
shell's environment. That is [vector
5](how-agents-leak-secrets.md#vector-5--supply-chain-malware-wearing-your-uid-harvests-credentials)
in the leak-vectors note, and byn's answer is structural.

Your shell holds no secret values under byn, because `byn exec` injects
only into the command it replaces itself with, and Composer was not that
command. The stealer's grab of environment variables comes back with
`PATH` and `HOME`. Cloud provider credentials are the same story: no
`~/.aws/credentials` exists when the keys live in the vault and are used
through `byn exec -- aws`, and the same holds for any provider whose CLI
reads its credential from the environment.

GitHub tokens need a caveat. A token held in the vault as `GH_TOKEN` or
`GITHUB_TOKEN` is not on disk. But Composer has a token of its own.
`auth.json`, under `~/.composer` or `~/.config/composer`, stores a GitHub
OAuth token in plaintext so Composer can fetch from GitHub without
hitting rate limits. Composer will also accept the same JSON through the
`COMPOSER_AUTH` environment variable, which byn can inject. The trouble
is that a plugin running inside `composer install` then reads it from
`process.env`. A package manager that executes code from the packages
it installs cannot be handed a secret it should not share, whichever
tool hands it over. The practical answer is a token scoped to read-only
public access, an explicit `allow-plugins` list in Composer's config,
`--no-plugins` where you can live with it, and Composer 2.10 or later,
whose policy config blocks Packagist-flagged malware versions by
default.

SSH keys are outside byn today. An `ssh` shim and file gating are on the
roadmap. This part of the haul was reachable no matter which
environment-secret manager you used.

The planted `.claude` and `.vscode` files are the interesting case. They
make an agent or an editor task run attacker code on the next open. That
agent then meets byn's gates: no session in its terminal, so reads get
`auth_required`; `--json` mode that fails instead of prompting; a `.byn`
pinlist it cannot extend without your master password; and an audit line
for every attempt. The injection is not stopped. The payoff is.

---

## Composer printed the token

On 13 May 2026 [Packagist
announced](https://blog.packagist.com/composer-2-9-8-and-2-2-28-fix-github-actions-token-disclosure-in-error-messages/)
Composer 2.9.8, 2.2.28 LTS and 1.10.28. GitHub had started rolling out a
new Actions token format that contains a hyphen. Composer's validation
rejected those tokens and printed the full token to stderr, which CI
systems save in job logs. The usual trigger was `shivammathur/setup-php`
automatically registering `GITHUB_TOKEN` in Composer's global
`auth.json`. Tokens for GitHub-hosted runners expire when the job ends
or after six hours; GitHub App installation tokens can carry broader
permissions and live longer. Packagist's advice was to update, look
through recent failed Composer runs for printed tokens, delete those
logs, and rotate.

byn's verdict is ✗, and the reason is simple: this happened on a CI
runner, and byn's domain ends at your machine. The lesson still carries.
Tools print what they are given. byn's own messages never include a
value (`Stored "DB_URL" in myapp/staging.`, never the value itself),
`byn get` adds a trailing newline only on a terminal, and nothing byn
does puts a value in a command line. But byn cannot police another
tool's error path. The best you can do is hand every tool the narrowest
credential it needs, so that on the day it prints one, it prints a
small one.

---

## Would another credential manager have helped?

For the Composer plugin, partly. Anything that takes values out of
`.env` and the shell, such as `op run`, Doppler or Infisical, shrinks
the same sweep. For PHP2Shell and the CI token leak, no developer-side
tool helps, byn included. byn's particular edge in the plugin case is
the one described in the [npm note](npm-october-2026-harvesters.md):
there is no standing grant for an installer to draw on, the pinlist
defaults to empty, and there is a per-access audit trail on the machine
where the install ran.

---

## What to do now

Patch PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 everywhere, including
development containers. If you cannot yet, apply PHP's interim settings
and restart the workers, and verify the settings through a live web
request rather than the CLI.

Check `composer.lock` for `intercom/intercom-php` 5.0.2, and look through
your repositories for the indicator files, especially setup scripts
under `.claude` and `.vscode` that you did not write.

Update Composer past 2.9.8 or 2.2.28, and review failed Actions runs
from late April for printed tokens.

Move your Laravel or Symfony `.env` values into byn: `byn import .env`,
confirm with `byn list`, delete the file, and start the dev server with
`byn exec -- php artisan serve` from a trusted `.byn` whose `[exec] env`
lists only what the application needs.

Never pin `composer install` in `[exec] actions`, and never run it with
secrets in scope. Set `allow-plugins` explicitly.

Read `byn audit tail` after dependency updates. If anything in the vault
was held by a process the plugin could reach, rotate it.

---

## Sources

- PHP, [GHSA-w8hw-w9fx-j79w: RCE via OOM corruption (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), 21 October 2026, and the [PHP 8.4.27 release](https://github.com/php/php-src/releases/tag/php-8.4.27).
- Sophos, [Advisory: PHP2Shell Vulnerabilities (CVE-2026-109618, CVE-2026-109619)](https://www.sophos.com/en-us/security-advisories/sophos-sa-20261021-php2shell), 21 to 28 October 2026.
- Semgrep, [Malicious Intercom PHP Package Spreads Mini Shai-Hulud Attack to Packagist via Composer Plugin](https://semgrep.dev/blog/2026/malicious-intercom-php-package-spreads-mini-shai-hulud-attack-to-packagist-via-composer-plugin/), 30 April 2026.
- Packagist, [Composer 2.9.8 and 2.2.28 fix GitHub Actions token disclosure in error messages](https://blog.packagist.com/composer-2-9-8-and-2-2-28-fix-github-actions-token-disclosure-in-error-messages/), 13 May 2026.

*Sources verified 30 October 2026. byn behaviour checked against the
v0.9.2 source and [the security model](../security.md). Reviewed and
re-stamped at each release.*

#!/bin/sh
# Tear down the byn service when the package is being REMOVED — and not when it
# is being upgraded.
#
# The distinction matters: an upgrade runs this too, and tearing the service
# down there would stop the daemon mid-upgrade and leave the new postinstall to
# rebuild it. Worse, the argument conventions differ per packager, so a script
# that ignores them removes the service on every upgrade:
#
#   deb   prerm  "upgrade" | "remove" | "deconfigure" ...
#   rpm   %preun 1 = upgrade, 0 = final removal
#   apk   pre-deinstall, no argument
#
# The vault is never touched. `byn setup --uninstall` keeps it by construction,
# and removing a package must not destroy the secrets it was managing.
set -eu

case "${1:-remove}" in
	1 | upgrade | deconfigure)
		exit 0 # an upgrade: leave the running service alone
		;;
esac

BYN=/usr/bin/byn
[ -x "$BYN" ] || BYN=/usr/local/bin/byn
[ -x "$BYN" ] || exit 0

# Best-effort. A failure here must not block the removal — a package that
# cannot be uninstalled is a worse problem than a service unit left behind,
# and `byn setup --uninstall` can still be run by hand afterwards.
if "$BYN" setup --uninstall >/dev/null 2>&1; then
	echo "byn: privilege separation removed (vault kept)"
else
	echo "byn: could not fully remove the byn service; run 'sudo byn setup --uninstall'" >&2
fi

exit 0

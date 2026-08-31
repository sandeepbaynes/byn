#!/bin/sh
# Provision privilege separation as part of installing the package.
#
# Runs as root, on both first install and upgrade, from deb/rpm/apk. The package
# manager has already asked for the password by this point, which is the moment
# to do the one privileged thing byn needs: create the service accounts, install
# the daemon service, and put the spawn helper in place with its file
# capabilities. Leaving it to a separate `sudo byn setup` meant every install
# was half an install, and the half that was missing is the isolation.
#
# `byn setup` is idempotent, so an upgrade re-runs it deliberately: the service
# unit and the helper change between releases, and a helper left behind by an
# older byn is a version-skew bug waiting to happen.
set -eu

BYN=/usr/bin/byn
[ -x "$BYN" ] || BYN=/usr/local/bin/byn

if [ ! -x "$BYN" ]; then
	echo "byn: installed binary not found; skipping privilege-separation setup" >&2
	exit 0
fi

# Never fail the package install over this. A machine without systemd, a
# container, a locked-down builder — byn still works there, just without
# privilege separation, and it says so in `byn doctor`. Breaking the install
# would be a worse trade than starting up degraded and honest about it.
if "$BYN" setup >/dev/null 2>&1; then
	echo "byn: privilege separation provisioned (daemon runs as _byn)"
else
	echo "byn: could not provision privilege separation automatically." >&2
	echo "byn: run 'sudo byn setup' to enable it, or 'byn doctor' to see why." >&2
fi

exit 0

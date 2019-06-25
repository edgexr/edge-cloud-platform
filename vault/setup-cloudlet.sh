#!/bin/bash

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <openrc-file> <cloudlet-name>" >&2
	exit 1
fi

OPENRC="$1"
CLOUDLETNAME="$2"

# exit immediately on failure
set -e

# Set up secrets engine
if ! vault secrets list | grep '^secret/' >/dev/null 2>&1; then
	echo "Setting up secrets engine"
	vault secrets enable -path=secret kv
fi

TMPFILE=$( mktemp )
trap 'rm -f "$TMPFILE"' EXIT

env - bash -c "source $OPENRC && $( dirname $0 )/openrc-to-json.py" >"$TMPFILE"
if [[ ! -s "$TMPFILE" ]]; then
	echo "Failed to generate openrc json" >&2
	exit 2
fi

vault kv put secret/cloudlet/openstack/${CLOUDLETNAME}/openrc.json @$TMPFILE

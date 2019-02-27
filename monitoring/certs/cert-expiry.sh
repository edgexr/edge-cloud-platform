#!/bin/bash
PATH='/usr/bin:/bin:/usr/local/bin'; export PATH

HOSTPORT="$1"
if [[ -z "$HOSTPORT" ]]; then
	echo "usage: $( basename $0 ) <host>[:<port>]" >&2
	exit 1
fi

[[ $( uname ) == "Darwin" ]] && DATE='gdate' || DATE='date'
$DATE --version 2>&1 | head -n 1 | grep GNU >/dev/null
if [[ $? -ne 0 ]]; then
	echo "ERROR: GNU coreutils date command not found" >&2
	exit 2
fi

HOST="${HOSTPORT%:*}"
PORT="${HOSTPORT#*:}"
[[ "$PORT" == "$HOSTPORT" ]] && PORT=443

EXPIRY=$( openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" </dev/null 2>/dev/null \
	| openssl x509 -noout -dates \
	| grep '^notAfter' \
	| cut -d= -f2- )

EXPIRY_EPOCH=$( $DATE --date="$EXPIRY" +'%s' )
NOW=$( $DATE '+%s' )

NDAYS=$(( ( EXPIRY_EPOCH - NOW ) / ( 24 * 60 * 60 ) ))
echo $NDAYS

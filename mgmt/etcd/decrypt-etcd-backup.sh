#!/bin/bash

set -e

ARTF_URL="$1"
if [[ -z "$ARTF_URL" ]]; then
    echo "usage: $( basename $0 ) <artf-etcd-backup-url>" >&2
    exit 1
fi

ARTF_BASE="${ARTF_URL%/*}"
ENCDB=$( basename "$ARTF_URL" )
ENCBASE=$( basename "$ENCDB" .db.gpg )
META="${ENCBASE}.json"

if [[ "$ENCDB" == "$ENCBASE" ]]; then
    # Not an entrypted etcd DB
    echo "URL of encrypted etcd DB should end in '.db.gpg'" >&2
    exit 2
fi

if [[ -z "$VAULT_ADDR" ]]; then
    export VAULT_ADDR="https://vault-main.mobiledgex.net"
    echo "VAULT_ADDR not set; assuming $VAULT_ADDR"
fi

if ! vault token lookup >/dev/null; then
    echo "Not logged in to vault" >&2
    exit 2
fi

read -p "Artifactory username: " ARTF_USER
read -s -p "Artifactory password: " ARTF_PASS; echo

log() {
    echo
    echo "== $* =="
}

TMPDIR=$( mktemp -d )
trap 'cd /tmp; rm -rf "$TMPDIR"' EXIT

cd "$TMPDIR"

log "Downloading $ENCDB"
curl -sf -u "${ARTF_USER}:${ARTF_PASS}" -O "${ARTF_BASE}/${ENCDB}"

log "Downloading $META"
curl -sf -u "${ARTF_USER}:${ARTF_PASS}" -O "${ARTF_BASE}/${META}"

log "Decrypting encryption key"
CIPHERTEXT=$( jq -r .ciphertext "$META" )
ENCKEY=$( vault write -field=plaintext transit/decrypt/etcd-backup \
        ciphertext="$CIPHERTEXT" \
        | base64 --decode )

log "Decrypting $ENCDB"
BKP="${ENCBASE}.db"
gpg --batch --passphrase "$ENCKEY" --decrypt "$ENCDB" >"$BKP"

log "Validating checksum"
SHA1SUM=$( openssl sha1 "$BKP" | awk '{print $NF}' )
ORIG_SHA1SUM=$( jq -r .original_sha1sum "$META" )
if [[ "$SHA1SUM" != "$ORIG_SHA1SUM" ]]; then
    echo "Checksum mismatch!" >&2
    exit 2
fi

ARTF_UPLOAD="${ARTF_BASE}/${BKP}"
log "Uploading unencrypted backup to Artifactory"
curl -f -u "${ARTF_USER}:${ARTF_PASS}" -XPUT -H "X-Checksum-Sha1: $SHA1SUM" \
    "$ARTF_UPLOAD" -T "$BKP"
echo

log "Upload complete"
echo "$ARTF_UPLOAD"

#!/bin/sh
CANAME=test-ca
SERVERNAME=test-server

if [ -n "$1" ]; then
    CANAME=$1
fi
if [ -n "$2" ]; then
    SERVERNAME=$2
fi

if [ -e out/${CANAME}.crt ]; then
    echo "certs exist"
    exit 0
fi

echo "generating CA..."
certstrap init --common-name ${CANAME} --passphrase ""

echo "generating server cert"
certstrap request-cert --domain ${SERVERNAME} --passphrase ""

echo "signing server cert"
certstrap sign --CA ${CANAME} ${SERVERNAME}

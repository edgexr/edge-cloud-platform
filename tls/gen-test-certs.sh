#!/bin/sh
CANAME=test-ca
SERVERNAME=test-server

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

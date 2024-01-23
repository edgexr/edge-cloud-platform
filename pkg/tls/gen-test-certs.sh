#!/bin/bash
set -e

CANAME=test-ca
SERVERNAME=test-server
CERTDIR=/tmp/edge-cloud-test-certs

on_err() {
    rm -Rf ${CERTDIR}
    exit 1
}
trap on_err ERR

if [ -n "$1" ]; then
    CANAME=$1
fi
if [ -n "$2" ]; then
    SERVERNAME=$2
fi
if [ -n "$3" ]; then
    CERTDIR=$3
fi

mkdir -p $CERTDIR
cd $CERTDIR

if [ -e out/${SERVERNAME}.crt ]; then
    echo "certs exist"
    exit 0
fi

echo "generating CA..."
certstrap init --common-name ${CANAME} --passphrase ""

echo "generating server cert"
certstrap request-cert --domain ${SERVERNAME},localhost --ip 127.0.0.1 --passphrase ""

echo "extracting public key"
openssl rsa -in out/${SERVERNAME}.key -pubout -out out/${SERVERNAME}.pub

echo "signing server cert"
certstrap sign --CA ${CANAME} ${SERVERNAME}

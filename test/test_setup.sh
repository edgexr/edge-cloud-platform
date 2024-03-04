#!/bin/bash

# This script installs dependencies needed for running unit, integration, and e2e tests.
set -e

INSTALL_DIR=/usr/local/bin
GO_INSTALL_DIR=/usr/local

GOVERS="1.21.6"
CERTSTRAP_VER=v1.3.0
VAULT_VER="1.11.2"
ETCD_VER=v3.5.12
INFLUXDB_VER="1.7.6"
REDIS_VER="7.0.7"

RELEASE=`lsb_release -d`
if [[ "$RELEASE" != *"Ubuntu"* ]]; then
    echo "This script is targeted for Ubuntu-based systems"
    exit 1
fi

if [[ ! -d ${GO_INSTALL_DIR}/go ]]; then
    echo "Installing go ${GOVERS}"
    wget -O /tmp/go${GOVERS}.tar.gz "https://dl.google.com/go/go${GOVERS}.linux-amd64.tar.gz" && tar -C ${GO_INSTALL_DIR} -xzf /tmp/go${GOVERS}
fi

if ! certstrap --version > /dev/null; then
    echo "Installing certstrap ${CERTSTRAP_VER}"
    wget -O ${INSTALL_DIR}/certstrap "https://github.com/square/certstrap/releases/download/${CERTSTRAP_VER}/certstrap-linux-amd64" && chmod a+x ${INSTALL_DIR}/certstrap
fi

if ! etcd --version > /dev/null; then
    echo "Installing Etcd ${ETCD_VER}"
    wget -O /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz "https://github.com/etcd-io/etcd/releases/download/${ETCD_VER}/etcd-${ETCD_VER}-linux-amd64.tar.gz" && tar xzvf /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz -C /tmp --strip-components=1 && mv /tmp/etcd-${ETCD_VER}-linux-amd64/etcd ${INSTALL_DIR} && mv /tmp/etcd-${ETCD_VER}-linux-amd64/etcdctl ${INSTALL_DIR} && mv /tmp/etcd-${ETCD_VER}-linux-amd64/etcdutl ${INSTALL_DIR}
fi

if ! vault --version > /dev/null; then
    echo "Installing Vault ${VAULT_VER}"
    wget -O /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VER}/vault_${VAULT_VER}_linux_amd64.zip" && unzip /tmp/vault.zip -d /tmp && mv /tmp/vault ${INSTALL_DIR}
fi

if ! influxd version > /dev/null; then
    echo "Installing InfluxDB ${INFLUXDB_VER}"
    wget -O /tmp/influxdb.deb "https://dl.influxdata.com/influxdb/releases/influxdb_${INFLUXDB_VER}_amd64.deb" && dpkg -i /tmp/influxdb.deb
fi

if ! redis-server --version > /dev/null; then
    echo "Installing Redis ${REDIS_VER}"
    apt-get update && apt-get install -y lsb-release gpg
    curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
    apt-get update && apt-get install -y redis
fi

if [[ "$PATH" != *"${GO_INSTALL_DIR}/go"* ]]; then
    echo "Complete, add ${GO_INSTALL_DIR}/go/bin to your PATH"
else
    echo "Complete"
fi

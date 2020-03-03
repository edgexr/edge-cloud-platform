#!/bin/sh

# exit immediately on failure
set -e

# Set up profiles for ansible access

# You may need to set the following env vars before running:
# VAULT_ADDR=http://127.0.0.1:8200
# VAULT_TOKEN=<my auth token>

# Deploy environment needs to be set
# ENVIRON=staging
ENVIRON=$1

if [ -z "$ENVIRON" ]; then
    echo "Usage: $( basename $0 ) <deploy-environment>"
    exit 1
fi
echo "Setting up Vault for ansible $ENVIRON environment"

cat > /tmp/ansible-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}

path "auth/approle/role/+/role-id" {
  capabilities = [ "read" ]
}

path "auth/approle/role/+/secret-id" {
  capabilities = [ "create", "update" ]
}

path "auth/approle/role/+/secret-id-accessor/destroy" {
  capabilities = [ "create", "update" ]
}

path "secret/data/approle/accessors/*" {
  capabilities = [ "create", "update", "read" ]
}

path "secret/metadata/approle/accessors/*" {
  capabilities = [ "list" ]
}

path "secret/data/ansible/${ENVIRON}/*" {
  capabilities = [ "read" ]
}

path "secret/data/ansible/common/*" {
  capabilities = [ "read" ]
}

path "secret/data/+/accounts/influxdb" {
  capabilities = [ "read" ]
}

path "secret/data/ansible/internal/accounts/influxdb" {
  capabilities = [ "read" ]
}

path "secret/data/registry/*" {
  capabilities = [ "read" ]
}

path "certs/*" {
  capabilities = [ "read" ]
}
EOF
vault policy write ${ENVIRON}.ansible /tmp/ansible-pol.hcl
rm /tmp/ansible-pol.hcl

vault write auth/approle/role/${ENVIRON}.ansible policies="${ENVIRON}.ansible" token_ttl=120

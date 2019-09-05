#!/bin/sh

# exit immediately on failure
set -e

# Set up profiles for ansible access

# You may need to set the following env vars before running:
# VAULT_ADDR=http://127.0.0.1:8200
# VAULT_TOKEN=<my auth token>

echo "Setting up Vault for ansible internal environment"

cat > /tmp/ansible-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}

path "secret/data/ansible/internal/*" {
  capabilities = [ "read" ]
}

path "secret/data/ansible/common/*" {
  capabilities = [ "read" ]
}

path "secret/data/certs/*" {
  capabilities = [ "read" ]
}
EOF
vault policy write internal.ansible /tmp/ansible-pol.hcl
rm /tmp/ansible-pol.hcl

vault write auth/approle/role/internal.ansible policies="internal.ansible" token_ttl=120

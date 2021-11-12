#!/bin/sh

# exit immediately on failure
set -e

# This collection of commands builds on the set in edge-cloud/vault/setup.sh
# It configures MC access.

vault secrets enable -path=jwtkeys kv
vault kv enable-versioning jwtkeys
sleep 1
vault write jwtkeys/config max_versions=2

# these are commented out but are used to set the mcorm secrets
#vault kv put jwtkeys/mcorm secret=12345 refresh=60m
#vault kv get jwtkeys/mcorm
#vault kv metadata get jwtkeys/mcorm

# set mcorm approle
cat > /tmp/mcorm-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}

path "jwtkeys/data/mcorm" {
  capabilities = [ "read" ]
}

path "jwtkeys/metadata/mcorm" {
  capabilities = [ "read" ]
}

path "secret/data/accounts/sql" {
  capabilities = [ "read" ]
}

path "secret/data/accounts/noreplyemail" {
  capabilities = [ "read" ]
}

path "secret/data/+/accounts/influxdb" {
  capabilities = [ "read" ]
}

path "secret/data/accounts/alertmanagersmtp" {
  capabilities = [ "read" ]
}

path "secret/data/accounts/gcs" {
  capabilities = [ "read" ]
}

path "secret/data/registry/*" {
  capabilities = [ "read" ]
}

path "pki-global/issue/*" {
  capabilities = [ "read", "update" ]
}

path "secret/data/accounts/chargify/*" {
  capabilities = [ "read" ]
}

path "secret/data/kafka/*" {
  capabilities = [ "read" ]
}

path "secret/data/federation/*" {
  capabilities = [ "create", "update", "delete", "read" ]
}
EOF

vault policy write mcorm /tmp/mcorm-pol.hcl
rm /tmp/mcorm-pol.hcl
vault write auth/approle/role/mcorm period="720h" policies="mcorm"
# get mcorm app roleID and generate secretID
vault read auth/approle/role/mcorm/role-id
vault write -f auth/approle/role/mcorm/secret-id

# set rotator approle - rotates mcorm secret
cat > /tmp/rotator-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}

path "jwtkeys/data/*" {
  capabilities = [ "create", "update", "read" ]
}

path "jwtkeys/metadata/*" {
  capabilities = [ "read" ]
}
EOF
vault policy write rotator /tmp/rotator-pol.hcl
rm /tmp/rotator-pol.hcl
vault write auth/approle/role/rotator period="720h" policies="rotator"
# get rotator app roleID and generate secretID
vault read auth/approle/role/rotator/role-id
vault write -f auth/approle/role/rotator/secret-id

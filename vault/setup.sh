#!/bin/sh
# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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

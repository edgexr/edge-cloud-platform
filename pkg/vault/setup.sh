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

# Set up the global settings for Vault.

# You may need to set the following env vars before running:
# VAULT_ADDR=http://127.0.0.1:8200
# VAULT_TOKEN=<my auth token>

echo "Setting up Vault"

TMP=$(mktemp -d -t ci-XXXXXXXX)

# vault audit enable file file_path="/tmp/vault.audit"

# enable approle if not already enabled
auths=$(vault auth list)
case "$auths" in
    *_"approle"_*) ;;
    *) vault auth enable approle
esac

if [ -z $CADIR ]; then
    CADIR=$TMP/vault_pki
fi
if [ -z $PKI_DOMAIN ]; then
    PKI_DOMAIN=internaldomain.net
fi

rm -Rf $CADIR
mkdir -p $CADIR

# enable kv version2 (default for dev vaults)
vault kv enable-versioning secret

# enable root pki
vault secrets enable pki
# generate root cert
vault write -format=json pki/root/generate/internal \
      common_name=localhost | jq -r '.data.certificate' > $CADIR/rootca.pem
vault write pki/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

# enable global intermediate pki
vault secrets enable -path=pki-global pki
vault secrets tune -max-lease-ttl=72h pki-global
vault write pki-global/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki-global/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki-global/crl"
# generate intermediate cert
vault write -format=json pki-global/intermediate/generate/internal \
      common_name="pki-global" | jq -r '.data.csr' > $CADIR/pki_global.csr
# sign intermediate with root
vault write -format=json pki/root/sign-intermediate csr=@$CADIR/pki_global.csr \
      format=pem_bundle | jq -r '.data.certificate' > $CADIR/global.cert.pem
# imported signed intermediate cert
vault write pki-global/intermediate/set-signed certificate=@$CADIR/global.cert.pem

# enable regional secure intermediate pki
vault secrets enable -path=pki-regional pki
vault secrets tune -max-lease-ttl=72h pki-regional
vault write pki-regional/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki-regional/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki-regional/crl"
# generate intermediate cert
vault write -format=json pki-regional/intermediate/generate/internal \
      common_name="pki-regional" | jq -r '.data.csr' > $CADIR/pki_regional.csr
# sign intermediate with root
vault write -format=json pki/root/sign-intermediate csr=@$CADIR/pki_regional.csr \
      format=pem_bundle | jq -r '.data.certificate' > $CADIR/regional.cert.pem
# imported signed intermediate cert
vault write pki-regional/intermediate/set-signed certificate=@$CADIR/regional.cert.pem

# enable regional cloudlet intermediate pki
vault secrets enable -path=pki-regional-cloudlet pki
vault secrets tune -max-lease-ttl=72h pki-regional-cloudlet
vault write pki-regional-cloudlet/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki-regional-cloudlet/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki-regional-cloudlet/crl"
# generate intermediate cert
vault write -format=json pki-regional-cloudlet/intermediate/generate/internal \
      common_name="pki-regional-cloudlet" | jq -r '.data.csr' > $CADIR/pki_cloudlet_regional.csr
# sign intermediate with root
vault write -format=json pki/root/sign-intermediate csr=@$CADIR/pki_cloudlet_regional.csr \
      format=pem_bundle | jq -r '.data.certificate' > $CADIR/cloudlet.regional.cert.pem
# imported signed intermediate cert
vault write pki-regional-cloudlet/intermediate/set-signed certificate=@$CADIR/cloudlet.regional.cert.pem

# set up global cert issuer role
vault write pki-global/roles/default \
      allow_localhost=true \
      allowed_domains="$PKI_DOMAIN" \
      allow_subdomains=true \
      allowed_uri_sans="region://none"

# set notifyroot approle - note this is a global service
cat > $TMP/notifyroot-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}

path "pki-global/issue/*" {
  capabilities = [ "read", "update" ]
}
EOF
vault policy write notifyroot $TMP/notifyroot-pol.hcl
rm $TMP/notifyroot-pol.hcl
vault write auth/approle/role/notifyroot period="720h" policies="notifyroot"
# get notifyroot app roleID and generate secretID
vault read auth/approle/role/notifyroot/role-id
vault write -f auth/approle/role/notifyroot/secret-id

# enable vault ssh secrets engine
vault secrets enable -path=ssh ssh
vault write ssh/config/ca generate_signing_key=true
vault write ssh/roles/machine -<<"EOH"
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "allowed_extensions": "permit-pty,permit-port-forwarding",
  "default_extensions": [
    {
      "permit-pty": "",
      "permit-port-forwarding": ""
    }
  ],
  "key_type": "ca",
  "default_user": "ubuntu",
  "ttl": "72h",
  "max_ttl": "72h"
}
EOH
vault write ssh/roles/user -<<"EOH"
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "allowed_extensions": "permit-pty,permit-port-forwarding",
  "default_extensions": [
    {
      "permit-pty": "",
      "permit-port-forwarding": ""
    }
  ],
  "key_type": "ca",
  "default_user": "ubuntu",
  "ttl": "5m",
  "max_ttl": "60m"
}
EOH

vault secrets enable -path=jwtkeys kv
vault kv enable-versioning jwtkeys
sleep 1
vault write jwtkeys/config max_versions=2

# these are commented out but are used to set the mcorm secrets
#vault kv put jwtkeys/mcorm secret=12345 refresh=60m
#vault kv get jwtkeys/mcorm
#vault kv metadata get jwtkeys/mcorm

# set mcorm approle
cat > $TMP/mcorm-pol.hcl <<EOF
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

path "secret/data/accounts/harbor" {
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
  capabilities = [ "read", "create", "update" ]
}

path "secret/data/accounts/mcldap" {
  capabilities = [ "create", "update", "read" ]
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

vault policy write mcorm $TMP/mcorm-pol.hcl
rm $TMP/mcorm-pol.hcl
vault write auth/approle/role/mcorm period="720h" policies="mcorm"
# get mcorm app roleID and generate secretID
vault read auth/approle/role/mcorm/role-id
vault write -f auth/approle/role/mcorm/secret-id

# set rotator approle - rotates mcorm secret
cat > $TMP/rotator-pol.hcl <<EOF
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
vault policy write rotator $TMP/rotator-pol.hcl
rm $TMP/rotator-pol.hcl
vault write auth/approle/role/rotator period="720h" policies="rotator"
# get rotator app roleID and generate secretID
vault read auth/approle/role/rotator/role-id
vault write -f auth/approle/role/rotator/secret-id

# alertmanager-sidecar approle
cat > $TMP/alertmgrsidecar-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}

path "secret/data/accounts/noreplyemail" {
  capabilities = [ "read" ]
}
EOF

vault policy write alertmgrsidecar $TMP/alertmgrsidecar-pol.hcl
rm $TMP/alertmgrsidecar-pol.hcl
vault write auth/approle/role/alertmgrsidecar period="720h" policies="alertmgrsidecar"
# get alertmgrsidecar app roleID and generate secretID
vault read auth/approle/role/alertmgrsidecar/role-id
vault write -f auth/approle/role/alertmgrsidecar/secret-id

rm -Rf $TMP

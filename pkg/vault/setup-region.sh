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

# Set up the profiles for the edge-cloud approles.
# This assumes a global Vault for all regions, so paths in the Vault
# are region-specific.
# This script should be run for each new region that we bring online.

# You may need to set the following env vars before running:
# VAULT_ADDR=http://127.0.0.1:8200
# VAULT_TOKEN=<my auth token>

# Region should be set to the correct region name
# REGION=local
REGION=$1

if [ -z "$REGION" ]; then
    echo "Usage: setup-region.sh <region>"
    exit 1
fi
echo "Setting up Vault region $REGION"

TMP=$(mktemp -d -t ci-XXXXXXXX)

if [ -z $PKI_DOMAIN ]; then
    PKI_DOMAIN=internaldomain.net
fi

# set up regional kv database
vault secrets enable -path=$REGION/jwtkeys kv
vault kv enable-versioning $REGION/jwtkeys
# time buffer required after new mount
# https://github.com/hashicorp/terraform-provider-vault/issues/677#issuecomment-609116328
# Code 400: Errors: Upgrading from non-versioned to versioned data. This backend will be unavailable for a brief period and will resume service shortly.
sleep 2
vault write $REGION/jwtkeys/config max_versions=2
vault secrets enable -path=$REGION/totp totp

# set up regional cert issuer role
vault write pki-regional/roles/$REGION \
      allow_localhost=true \
      allowed_domains="$PKI_DOMAIN" \
      allow_subdomains=true \
      allowed_uri_sans="region://$REGION"

# set up cloudlet regional cert issuer role
vault write pki-regional-cloudlet/roles/$REGION \
      allow_localhost=true \
      allowed_domains="$PKI_DOMAIN" \
      allow_subdomains=true \
      allowed_uri_sans="region://$REGION"

cat > $TMP/controller-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}
path "secret/data/registry/*" {
  capabilities = [ "read" ]
}
path "secret/data/$REGION/*" {
  capabilities = [ "create", "update", "delete", "read" ]
}
path "secret/metadata/$REGION/*" {
  capabilities = [ "delete" ]
}
path "secret/data/cloudlet/*" {
  capabilities = [ "read" ]
}
path "secret/data/$REGION/accounts/*" {
  capabilities = [ "read" ]
}
path "secret/data/accounts/chef" {
  capabilities = [ "read" ]
}
path "secret/data/accounts/gcs" {
  capabilities = [ "read" ]
}
path "pki-regional/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
path "pki-regional-cloudlet/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
path "ssh/sign/machine" {
  capabilities = [ "create", "update" ]
}
path "secret/data/kafka/$REGION/*" {
  capabilities = [ "create", "update", "delete", "read" ]
}
path "$REGION/totp/keys/*" {
  capabilities = [ "create", "update", "delete", "read" ]
}
path "$REGION/totp/code/*" {
  capabilities = [ "read" ]
}
path "secret/data/federation/*" {
  capabilities = [ "read" ]
}
path "secret/data/accounts/dnsprovidersbyzone/*" {
  capabilities = [ "read" ]
}
EOF
vault policy write $REGION.controller $TMP/controller-pol.hcl
rm $TMP/controller-pol.hcl
vault write auth/approle/role/$REGION.controller period="720h" policies="$REGION.controller"
# get controller app roleID and generate secretID
vault read auth/approle/role/$REGION.controller/role-id
vault write -f auth/approle/role/$REGION.controller/secret-id

# set dme approle
cat > $TMP/dme-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}
path "$REGION/jwtkeys/data/dme" {
  capabilities = [ "read" ]
}
path "$REGION/jwtkeys/metadata/dme" {
  capabilities = [ "read" ]
}
# Allow access to certs (including access to cert creation)
path "certs/*" {
  capabilities = ["read"]
}
path "pki-regional/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
path "pki-regional-cloudlet/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
path "/secret/data/accounts/gddt/*" {
    capabilities = [ "read" ]
}
EOF
vault policy write $REGION.dme $TMP/dme-pol.hcl
rm $TMP/dme-pol.hcl
vault write auth/approle/role/$REGION.dme period="720h" policies="$REGION.dme"
# get dme app roleID and generate secretID
vault read auth/approle/role/$REGION.dme/role-id
vault write -f auth/approle/role/$REGION.dme/secret-id

# set cluster-svc approle
cat > $TMP/cluster-svc-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}
path "pki-regional/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
EOF
vault policy write $REGION.cluster-svc $TMP/cluster-svc-pol.hcl
rm $TMP/cluster-svc-pol.hcl
vault write auth/approle/role/$REGION.cluster-svc period="720h" policies="$REGION.cluster-svc"
# get cluster-svc app roleID and generate secretID
vault read auth/approle/role/$REGION.cluster-svc/role-id
vault write -f auth/approle/role/$REGION.cluster-svc/secret-id

# set rotator approle - rotates dme secret
cat > $TMP/rotator-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}
path "$REGION/jwtkeys/data/*" {
  capabilities = [ "create", "update", "read" ]
}
path "$REGION/jwtkeys/metadata/*" {
  capabilities = [ "read" ]
}
EOF
vault policy write $REGION.rotator $TMP/rotator-pol.hcl
rm $TMP/rotator-pol.hcl
vault write auth/approle/role/$REGION.rotator period="720h" policies="$REGION.rotator"
# get rotator app roleID and generate secretID
vault read auth/approle/role/$REGION.rotator/role-id
vault write -f auth/approle/role/$REGION.rotator/secret-id

# generate secret string:
# openssl rand -base64 128

# Generate regional cert for edgectl
mkdir -p /tmp/edgectl.$REGION
vault write -format=json pki-regional/issue/$REGION \
      common_name=edgectl.$PKI_DOMAIN \
      alt_names=localhost \
      ip_sans="127.0.0.1,0.0.0.0" \
      uri_sans="region://$REGION" > /tmp/edgectl.$REGION/issue
cat /tmp/edgectl.$REGION/issue | jq -r .data.certificate > /tmp/edgectl.$REGION/mex.crt
cat /tmp/edgectl.$REGION/issue | jq -r .data.private_key > /tmp/edgectl.$REGION/mex.key
cat /tmp/edgectl.$REGION/issue | jq -r .data.issuing_ca > /tmp/edgectl.$REGION/mex-ca.crt

# set edgeturn approle
cat > $TMP/edgeturn-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}
path "pki-regional/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
EOF
vault policy write $REGION.edgeturn $TMP/edgeturn-pol.hcl
rm $TMP/edgeturn-pol.hcl
vault write auth/approle/role/$REGION.edgeturn period="720h" policies="$REGION.edgeturn"
# get edgeturn app roleID and generate secretID
vault read auth/approle/role/$REGION.edgeturn/role-id
vault write -f auth/approle/role/$REGION.edgeturn/secret-id

# autoprov approle
# Just need access to influx db credentials
cat > $TMP/autoprov-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}
path "secret/data/+/accounts/influxdb" {
  capabilities = [ "read" ]
}
path "pki-regional/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
EOF
vault policy write $REGION.autoprov $TMP/autoprov-pol.hcl
rm $TMP/autoprov-pol.hcl
vault write auth/approle/role/$REGION.autoprov period="720h" policies="$REGION.autoprov"
# get autoprov app roleID and generate secretID
vault read auth/approle/role/$REGION.autoprov/role-id
vault write -f auth/approle/role/$REGION.autoprov/secret-id

# frm approle
cat > $TMP/frm-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}
path "secret/data/cloudlet/*" {
  capabilities = [ "read" ]
}
path "secret/data/federation/*" {
  capabilities = [ "read" ]
}
path "pki-regional/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
EOF
vault policy write $REGION.frm $TMP/frm-pol.hcl
rm $TMP/frm-pol.hcl
vault write auth/approle/role/$REGION.frm period="720h" policies="$REGION.frm"
# get frm app roleID and generate secretID
vault read auth/approle/role/$REGION.frm/role-id
vault write -f auth/approle/role/$REGION.frm/secret-id

# Note: Shepherd uses CRM's Vault access creds.

rm -Rf $TMP

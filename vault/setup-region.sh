#!/bin/sh

# exit immediately on failure
set -e

REGION=$1

if [ -z "$REGION" ]; then
    echo "Usage: setup-region.sh <region>"
    exit 1
fi
echo "Setting up infra Vault region $REGION"

# autoprov approle
# Just need access to influx db credentials
cat > /tmp/autoprov-pol.hcl <<EOF
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
vault policy write $REGION.autoprov /tmp/autoprov-pol.hcl
rm /tmp/autoprov-pol.hcl
vault write auth/approle/role/$REGION.autoprov period="720h" policies="$REGION.autoprov"
# get autoprov app roleID and generate secretID
vault read auth/approle/role/$REGION.autoprov/role-id
vault write -f auth/approle/role/$REGION.autoprov/secret-id

# frm approle
cat > /tmp/frm-pol.hcl <<EOF
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}

path "pki-regional/issue/$REGION" {
  capabilities = [ "read", "update" ]
}
EOF
vault policy write $REGION.frm /tmp/frm-pol.hcl
rm /tmp/frm-pol.hcl
vault write auth/approle/role/$REGION.frm period="720h" policies="$REGION.frm"
# get frm app roleID and generate secretID
vault read auth/approle/role/$REGION.frm/role-id
vault write -f auth/approle/role/$REGION.frm/secret-id

# Note: Shepherd uses CRM's Vault access creds.

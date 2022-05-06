## Development Setup

### Vault Init

```
mkdir -p $HOME/vault-plugins

cat >$HOME/vault.hcl <<EOT
plugin_directory = "$HOME/vault-plugins"
EOT

vault server -dev -config=$HOME/vault.hcl
```

### Certgen Backend Init

```
mkdir -p $HOME/vault-certs

MEX_CF_USER=mobiledgex.ops@mobiledgex.com
MEX_CF_KEY=...

TAG=$USER-$( date +%Y-%m-%d )
cd docker
TAG=$TAG make build
docker run --rm \
	-p 4567:4567 \
	-e RAILS_ENV=production \
	-e RACK_ENV=production \
	-e LETSENCRYPT_ENV=staging \
	-e CF_USER=$MEX_CF_USER \
	-e CF_APIKEY=$MEX_CF_KEY \
	-e NS1_APIKEY=foo \
	-v $HOME/vault-certs:/etc/letsencrypt \
	registry.mobiledgex.net:5000/mobiledgex/certgen:$TAG
```

### Vault Plugin Install

```
export VAULT_ADDR='http://127.0.0.1:8200'

make
cp letsencrypt-plugin $HOME/vault-plugins
SUM=$( shasum -a 256 letsencrypt-plugin | awk '{print $1}' )
vault secrets disable certs
vault write sys/plugins/catalog/letsencrypt-certs sha_256="$SUM" command=letsencrypt-plugin
vault secrets enable -path=certs -plugin-name=letsencrypt-certs plugin
```

### Test

```
export VAULT_ADDR='http://127.0.0.1:8200'
vault read certs/cert/foo.mobiledgex.net
vault read -format=json certs/list
```

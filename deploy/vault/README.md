# Vault

On gcp.

Installed in vault.mobiledgex.net.

## first time run

```
docker-compose up -d --build
```

Builds the docker images of consul and vault.

## certificates

```
gen-cert-vault-moiledgex.sh
```


## HTTPS

Nginx at 443

```
run-nginx-vault-proxy.sh
```


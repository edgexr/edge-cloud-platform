## Generate an offline root CA for vault

```
sed "s|<FIXME>|`pwd`|" openssl.cnf.tmpl >openssl.cnf

chmod 700 private
touch index.txt
echo 1000 > serial

openssl genrsa -aes256 -out private/ca.key.pem 4096

openssl req -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 \
    -sha256 -extensions v3_ca -out certs/ca.cert.pem
### Set Common Name = MobiledgeX Root CA

chmod 400 private/ca.key.pem
chmod 444 certs/ca.cert.pem
```

### Verify the root CA certificate

```
openssl x509 -noout -text -in certs/ca.cert.pem
```

## Generate a CSR from vault

```
vault write -format=json pki/intermediate/generate/internal \
    common_name="MobiledgeX Vault Intermediate CA" \
    | jq -r '.data.csr' > intermediate.csr.pem
```

## Generate the intermediate CA certificate

```
openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
    -days 7300 -notext -md sha256 \
    -in intermediate.csr.pem \
    -out intermediate.cert.pem
```

### Verify the intermediate CA certificate

```
openssl x509 -noout -text -in intermediate.cert.pem
openssl verify -CAfile certs/ca.cert.pem intermediate.cert.pem
```

## Import the intermediate CA certificate into vault:

```
vault write pki/intermediate/set-signed \
    certificate=@intermediate.cert.pem
```

## Store the root CA certificate and key _very_ securely offline:

* `private/ca.key.pem`
* `certs/ca.cert.pem`

## Store the root CA certificate _only_ in vault

```
vault kv put secret/certs/root-ca cert=@certs/ca.cert.pem
```

## References

* https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html

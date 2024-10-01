## e2e testing

### Testing with DNS

If you are testing app instance deployment with DNS, you will need to
set up things to be able to register DNS entries.

Change the domain/zone below and your cloudflare API credential
accordingly.

```
export DNSDOMAIN=my.edgexr.org
export DNSZONE=edgexr.org
export CLOUDFLARE_APIKEY=<apikey>
```

From director repo, start e2e tests:
```
make test-start-dns
```

### Testing without DNS

If testing without DNS, you can run the regular e2e test start:

```
make test-start
```

### Login as admin
```
mcctl --skipverify --addr=https://localhost:9900 login username=mexadmin password=mexadminfastedgecloudinfra
```

### Reset regional settings

This resets the timeouts for cluster create, etc, which are set low
for testing but should be reset to their higher default values for
real infrastructure.

```
mcctl --skipverify --addr=https://localhost:9900 settings reset region=local
```

### Create a Zone
```
mcctl --skipverify --addr=https://localhost:9900 zone create region=local org=dmuus name=azurecloud
```

### Create a Cloudlet

First set environment variables needed for following cloudlet create command.

```
mcctl --skipverify --addr https://localhost:9900 cloudlet create \
region=local cloudlet=azurecloud \
cloudletorg=dmuus location.latitude=50.72248 location.longitude=7.1422 \
numdynamicips=20 platformtype=azure zone=azurecloud \
"envvar=AZURE_LOCATION=westus" \
"accessvars=AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID" \
"accessvars=AZURE_TENANT_ID=$AZURE_TENANT_ID" \
"accessvars=AZURE_CLIENT_ID=$AZURE_CLIENT_ID" \
"accessvars=AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET" \
"accessvars=AZURE_RESOURCE_GROUP=$AZURE_RESOURCE_GROUP"
```

### Run whatever tests you want

For example, the robot QA appinst_k8s acceptance test.

### Clean up Cloudlet
```
mcctl --skipverify --addr https://localhost:9900 cloudlet delete \
region=local cloudlet=azurecloud cloudletorg=dmuus
```

### Clean up Zone
```
mcctl --skipverify --addr=https://localhost:9900 zone delete region=local org=dmuus name=azurecloud
```

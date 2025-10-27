# Test Cluster API with e2e

This tests the cluster API with e2e processes.
This assumes you have a cluster API management cluster configured
as in [README_clusterapi_k3s.md](./README_clusterapi_k3s.md).

Set up the local e2e processes from edge-cloud-director using
```
make test-start
```

## Log in and set timeouts
```
mcctl --skipverify --addr=https://localhost:9900 login username=mexadmin \
  password=mexadminfastedgecloudinfra
mcctl --skipverify --addr=https://localhost:9900 settings update \
  region=local createcloudlettimeout=180s \
  createappinsttimeout=180s createclusterinsttimeout=600s \
  deleteclusterinsttimeout=600s
mcctl --skipverify --addr=https://localhost:9900 zone create region=local \
  name=baremetal org=dmuus
```

## Create Cloudlet

Set KC to the contents of the kubeconfig pointing to the k3s
capi management cluster
```
KC=$(cat /home/gainsley/go/src/github.com/edgexr/cluster-api-local/k3s.yaml)
```

Cloudlet create command:
```
mcctl --skipverify --addr=https://localhost:9900 cloudlet create \
  region=local cloudlet=baremetal cloudletorg=dmuus \
  location.latitude=40 location.longitude=50 \
  zone=baremetal numdynamicips=20 platformtype=clusterapi \
  "accessvars=Kubeconfig=$KC" \
  envvar=ManagementNamespace=dc1 \
  envvar=InfrastructureProvider=metal3 \
  envvar=FloatingVIPs=192.168.222.201 \
  envvar=FloatingVIPsSubnet=24 \
  envvar=ImageURL="http://192.168.50.143/UBUNTU_24.04_NODE_IMAGE_K8S_v1.34.1.qcow2" \
  envvar=ImageFormat=qcow2 \
  envvar=ImageChecksum=8bf730abc51e08ec87eb530c2595d25ff2ba2b51e08e60f6688c50b8bcf099d9 \
  envvar=ImageChecksumType=sha256
```

## Create a Cluster
```
mcctl --skipverify --addr=https://localhost:9900 clusterinst create \
  region=local cluster=bm1 clusterorg=AcmeAppCo \
  zone=baremetal zoneorg=dmuus  \
  kubernetesversion=v1.34.1 \
  nodepools:0.name=workers nodepools:0.numnodes=1 \
  nodepools:0.noderesources.vcpus=1 nodepools:0.noderesources.ram=1024
```

## Create an App
```
mcctl --skipverify --addr=https://localhost:9900 app create \
  region=local apporg=AcmeAppCo appname=app1 appvers="1.0" \
  imagepath=nginxdemos/hello:0.4 \
  deployment=kubernetes accessports=http:80:tls \
  kubernetesresources.cpupool.totalvcpus=0.1 \
  kubernetesresources.cpupool.totalmemory=100 \
  kubernetesresources.cpupool.topology.minnodevcpus=1 \
  isstandalone=false kubernetesresources.minkubernetesversion="1.30" \
  allowserverless=true
```

## Create an AppInst
```
mcctl --skipverify --addr=https://localhost:9900 appinst create \
  region=local appinstorg=AcmeAppCo appinstname=app1 \
  apporg=AcmeAppCo appname=app1 appvers=1.0 \
  zone=baremetal zoneorg=dmuus
```

## Cleanup

Delete AppInst
```
mcctl --skipverify --addr=https://localhost:9900 appinst delete \
  region=local appinstorg=AcmeAppCo appinstname=app1
```

Delete Cluster
```
mcctl --skipverify --addr=https://localhost:9900 clusterinst delete \
  region=local cluster=bm1 clusterorg=AcmeAppCo
```

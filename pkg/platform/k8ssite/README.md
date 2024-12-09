## Kubernetes Cluster as a Cloudlet

K8s Site is a platform that leverages a single Kubernetes cluster as
an edge site. The cluster can be configured either as multi-tenant
cluster or as a cluster dedicated to a single developer organization.

## Local Testing

A k8ssite cloudlet can be tested locally using e2e tests.
For the Kubernetes cluster we use a [k3d](https://k3d.io/stable/#other-installers) local cluster.

### Create local cluster

```bash
k3d cluster create testcluster --k3s-arg "--disable=traefik@server:0" -p "8080:80@loadbalancer" -p "8443:443@loadbalancer"
```

This creates a local k3d cluster with Traefik disabled, because
edge cloud will install ingress-nginx. The `-p` options are optional,
they can be used to remap the ingress ports from the normal 80/443
ports to something less likely to conflict on your local machine.

Note this will also add the k3d kubeconfig to your local ~/.kube/config
as the default context.

```bash
export KC=$(k3d kubeconfig get testcluster)
```
Export the k3d kubeconfig as an environment variable, which will get
passed to the create cloudlet command.

After testing is finished, the cluster can be deleted by:
```bash
k3d cluster delete testcluster
```

### Run e2e tests

From the edge-cloud-director repo, run:
```bash
make test-start
```

This will start the edge cloud platform locally.
Use `make test-stop` when done.

### Set up Cloudlet

```bash
mcctl --skipverify --addr=https://localhost:9900 login username=mexadmin password=mexadminfastedgecloudinfra
mcctl --skipverify --addr=https://localhost:9900 settings update region=local createcloudlettimeout=30s createappinsttimeout=60s
mcctl --skipverify --addr=https://localhost:9900 zone create region=local \
  name=k3d org=dmuus
```

This will log in as admin, update the settings for longer timeouts,
and create a test zone.

```bash
mcctl --skipverify --addr=https://localhost:9900 cloudlet create region=local \
  cloudlet=k3d cloudletorg=dmuus location.latitude=40 location.longitude=50 \
  zone=k3d numdynamicips=20 platformtype=k8ssite "accessvars=KUBECONFIG=$KC" \
  envvar=INGRESS_HTTP_PORT=8080 \
  envvar=INGRESS_HTTPS_PORT=8443
```

Run the above command to create a cloudlet from the k3d cluster.
The kubeconfig for the k3d cluster is passed as an access var.
The ingress env vars are optional, in case we've remapped the ingress
ports for k3d, or we have a NAT/reverse proxy fronting the k3d
cluster. Finally, if there is a NAT/reverse proxy, then optionally
add to the command `envvar=EXTERNAL_IP_MAP=extIP=intIP`, replacing
`extIP` and `intIP` with your actual IPs, to specify the mapping from
the external NAT IP to the internal k3d ingress IP.

### Deploy Application

```bash
mcctl --skipverify --addr=https://localhost:9900 app create region=local \
  apporg=AcmeAppCo appname=test appvers=1.0 \
  imagepath=hashicorp/http-echo:1.0 deployment=kubernetes \
  kubernetesresources.cpupool.totalvcpus=0.1 \
  kubernetesresources.cpupool.totalmemory=100 \
  accessports=http:5678:tls allowserverless=true
```

This defines a simple application based on http-echo which will
report `hello-world` when queried. Note that port 5678's protocol
is http, which will map it to the ingress.

```bash
mcctl --skipverify --addr=https://localhost:9900 appinst create region=local \
  appinstorg=AcmeAppCo appinstname=test apporg=AcmeAppCo appname=test appvers=1.0 \
  zonekey.name=k3d zonekey.organization=dmuus
```

The above will deploy the application. Once the application is deployed,
it can be reached via curl to the ingress IP, or you can add the
hostname mapping `k3d-ip shared.k3d-dmuus.local.edgecloude2e.net` to `/etc/hosts` to access via URL, replacing `k3d-ip` with your actual
k3d ingress IP, or the external NAT IP.

```bash
curl -k -v https://shared.k3d-dmuus.local.edgecloude2e.net:8443
```

Note the `-k` option to skip certificate verification, as this is a
test setup so the ingress is given a self-signed certificate.

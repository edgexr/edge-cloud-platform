# registry

On gcp. Installed at registry.mobiledgex.net

maven, docker registry and file server.
They are run as docker containers.

## auth/

credentials, certificates, etc.

## gen-cert-registry-mobiledgex.sh

get letsencrypt certs for registry

## run-docker-registry.sh

docker registry runs at port 5000.

## gen-htpasswd.sh

generate htpasswd for use with the above docker registry container image

## run-gohttpserver.sh

https file server at 8000.

## run-nexus-simple.sh

maven repo at 8081, but exposed via https at 443 via nginx proxy below.

## run-nginx-nexus-proxy.sh

TLS termination for nexus at 443.


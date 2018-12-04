docker run -d \
       -p 5000:5000 \
       --restart=always \
       --name docker-registry \
       -v `pwd`/auth:/auth \
       -v /home/bob/docker-registry:/var/lib/registry \
       -e "REGISTRY_AUTH=htpasswd" \
       -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
       -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
       -v `pwd`/certs:/certs \
       -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/fullchain.cer \
       -e REGISTRY_HTTP_TLS_KEY=/certs/registry.mobiledgex.net.key \
       registry:2

#docker run -d -p 5000:5000 --restart always --name registry registry:2

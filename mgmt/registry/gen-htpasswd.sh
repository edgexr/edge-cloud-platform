docker run --entrypoint htpasswd registry:2 -Bbn bob Keon >> auth/htpasswd
docker run --entrypoint htpasswd registry:2 -Bbn mobiledgex sandhill >> auth/htpasswd

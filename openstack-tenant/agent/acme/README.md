# ACME autocert via letsencrypt

To generate proper CA issued certficates `acme.sh` docker image can be used:

```
docker run --rm  -it -e CF_Key="yourkey" -e CF_Email="youremail@gmail.com"   -v "$(pwd)/out":/acme.sh    --net=host   neilpang/acme.sh  --issue -d yourdomain.gq   --dns dns_cf
```

This method uses cloudflare API to directly insert required TXT records for callback verification during ACME protocol phase.
This seems to be the most reliable method.

The letsencrypt service limits the number of API calls per week.
To avoid getting locked out from letsencrypt, during development phase, you can use `--staging` flag.
To overwrite the existing certificates, use `--force` flag.
To debug the ACME protocol progress, use `--debug` flag.

When successful certficiates are generated, they will be saved under `out` directory.

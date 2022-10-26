#!/bin/sh
docker run --rm -d -p 1081:80 -v "$PWD/:/usr/share/nginx/html/doc" -e SPEC_URL=doc/FederationApi_v1.3.0.yaml redocly/redoc

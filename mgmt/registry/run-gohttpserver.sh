#!/bin/bash
docker run -d --rm -p 8000:8000 -v /home/bob/certs:/certs -v /home/bob/files-repo:/app/public --name gohttpserver codeskyblue/gohttpserver ./gohttpserver --root /app/public --auth-type http --auth-http mobiledgex:sandhill --cors --upload --delete --title mobiledgex --cert=/certs/cert.pem --key=/certs/key.pem

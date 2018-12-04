#!/bin/bash
docker run -d --restart always --net host --name nginx-vault-proxy -v /home/bob/auth/nginx-vault:/etc/nginx nginx

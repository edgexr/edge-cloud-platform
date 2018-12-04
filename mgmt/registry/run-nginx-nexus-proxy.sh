#!/bin/bash
docker run -d --restart always --net host --name nginx-nexus-proxy -v /home/bob/auth/nginx-nexus:/etc/nginx nginx

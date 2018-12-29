#!/bin/bash
set -x
for i in  overlays/*; do
    kustomize build $i > output/$(basename $i).yaml  
done
# bogus 0 length output for docker-compose example
rm output/stackdemo.yaml
cp base/docker-swarm/stackdemo/docker-compose.yml output/stackdemo.yaml

#!/bin/bash
set -x
for i in  overlays/*; do
    kustomize build $i > output/$(basename $i).yaml  
done

#!/bin/sh
# https://openapi-generator.tech/docs/generators/go
TOP=../..
PKG=fedewapi
DIR=pkg/$PKG

docker run --rm -u `id -u $USER`:`id -g $USER` \
    -v $PWD/../..:/local openapitools/openapi-generator-cli@sha256:c849dfbe404e6740de63cc4f9d2534e17659eb8b26deb058e23924e459957560 generate \
    -i /local/doc/fedapi/FederationApi_v1.3.0.yaml \
    -g go \
    -o /local/$DIR \
    --global-property models,modelDocs=false,modelTests=false,skipFormModel=false \
    -p packageName=$PKG,disallowAdditionlPropertiesIfNotPresent=false,enumClassPrefix=true
# clean up client files we don't need, we just want the structs
cd $TOP/$DIR
rm response.go go.mod go.sum git_push.sh client.go configuration.go api_*.go .gitignore .openapi-generator-ignore .travis.yml
rm -R api docs test .openapi-generator

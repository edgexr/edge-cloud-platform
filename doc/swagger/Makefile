# generate swagger 2.0 documentation

TOP	= ../..

# This generates spec by parsing swagger annotations in go files.
# Some of the comments are auto-generated from mc2 generator reading proto files,
# so this ensures those files are generated.
doc:
	(cd $(HOME); go install github.com/go-swagger/go-swagger/cmd/swagger@latest)
	go install \
		$(TOP)/tools/protoc-gen-mc2 \
		$(TOP)/tools/swaggerfix
	make -C $(TOP)/api/edgeproto docgen
	swagger generate spec -w $(TOP) -i ./init.json -o ./apidocs.swagger.json --scan-models
	swaggerfix --custom ./custom.yaml ./apidocs.swagger.json

doc-local-server:
	docker run --rm -p 1081:80 \
		-v "$(shell pwd)/apidocs.swagger.json:/usr/share/nginx/html/swagger.json" \
		-e SPEC_URL=swagger.json \
		-e REDOC_OPTIONS='sort-props-alphabetically=\"true\"' \
		redocly/redoc:v2.0.0-rc.23

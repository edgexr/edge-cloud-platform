# generate openapi 3.0 documentation

DEPS		:= $(shell go list -f '{{ .Dir }}' -m \
	github.com/gogo/protobuf)
PROTOTYPES	:= $(word 1,$(DEPS))/types
TOP		= ../..
OUTFILE		= mc-openapi.yaml
SCANPATHS	= --scanPath $(TOP)/api/ormapi \
		--scanPath $(TOP)/api/edgeproto \
		--scanPath $(TOP)/api/dme-proto \
		--scanPath $(TOP)/pkg/billing \
		--scanPath $(TOP)/pkg/cloudcommon/node/events.go \
		--scanPath $(PROTOTYPES)

doc:
	go install \
		$(TOP)/tools/protoc-gen-mc2 \
		$(TOP)/tools/gen-mc-openapi
	make -C $(TOP)/api/edgeproto docgen
	gen-mc-openapi -baseFile mcbase.yaml -outFile $(OUTFILE) $(SCANPATHS)

debug:
	go install $(TOP)/tools/gen-mc-openapi
	gen-mc-openapi -baseFile mcbase.yaml -outFile $(OUTFILE) $(SCANPATHS)

local-server:
	docker run --rm -p 1081:80 -v "$(shell pwd)/:/usr/share/nginx/html/doc" -e SPEC_URL=doc/$(OUTFILE) redocly/redoc

lint:
	redocly lint --config redocly.config mc-openapi.yaml

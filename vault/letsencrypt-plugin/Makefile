VERSION		= 1.2
GITCOMMIT	= $(shell git describe --always --dirty=+)
VERSION_FILE	= letsencrypt/version.go

COMPILE_ENV	=

build-linux: COMPILE_ENV = CGO_ENABLED=0 GOOS=linux GOARCH=amd64

build: $(VERSION_FILE)
	$(COMPILE_ENV) go build .

build-linux: build

$(VERSION_FILE): FORCE
	sed -e 's/{{VERSION}}/$(VERSION)/' -e 's/{{GITCOMMIT}}/$(GITCOMMIT)/' $@.tmpl >$@

clean: FORCE
	$(RM) $(VERSION_FILE)

FORCE:

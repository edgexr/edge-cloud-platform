VERSION		= 1.0
GITCOMMIT	= $(shell git describe --always --dirty=+)
VERSION_FILE	= letsencrypt/version.go

COMPILE_ENV	=

build-linux: COMPILE_ENV = CGO_ENABLED=0 GOOS=linux GOARCH=amd64

build: $(VERSION_FILE)
	$(COMPILE_ENV) go build .

build-linux: build

$(VERSION_FILE): $(VERSION_FILE).tmpl
	sed -e 's/{{VERSION}}/$(VERSION)/' -e 's/{{GITCOMMIT}}/$(GITCOMMIT)/' $< >$@

clean:
	$(RM) $(VERSION_FILE)

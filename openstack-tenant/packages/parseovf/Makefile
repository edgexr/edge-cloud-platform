PACKAGE = parseovf
VERSION = 0.2

DISTRIBUTION = cirrus
COMPONENT = main

PKGDIR = $(PACKAGE)_$(VERSION)

all: build
	../build.sh $(PACKAGE) $(VERSION) $(DISTRIBUTION) $(COMPONENT)

build:
	mkdir -p $(PKGDIR)/usr/local/bin
	GOOS=linux GOARCH=amd64 go build -o $(PKGDIR)/usr/local/bin/parseovfenv \
	     ../../../crm-platforms/vcd/parseovf

clean:
	$(RM) -r $(PKGDIR)
	$(RM) $(PKGDIR).deb $(DOWNLOAD)

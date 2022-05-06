PACKAGE = helm
VERSION = 3.4.2
SHA256SUM = cacde7768420dd41111a4630e047c231afa01f67e49cc0c6429563e024da4b98

DISTRIBUTION = cirrus
COMPONENT = main

PKGURL = https://get.helm.sh/helm-v$(VERSION)-linux-amd64.tar.gz
DOWNLOAD = helm.tar.gz

PKGDIR = $(PACKAGE)_$(VERSION)

all: setup_files
	../build.sh $(PACKAGE) $(VERSION) $(DISTRIBUTION) $(COMPONENT)

setup_files:
	mkdir $(PKGDIR)
	mkdir -p $(PKGDIR)/usr/local/bin
	wget -O $(DOWNLOAD) $(PKGURL)
	test `sha256sum $(DOWNLOAD) | awk '{print $$1}'` == $(SHA256SUM)
	tar xf $(DOWNLOAD) linux-amd64/helm
	mv linux-amd64/helm $(PKGDIR)/usr/local/bin/helm
	chmod a+x $(PKGDIR)/usr/local/bin/helm

clean:
	$(RM) -r $(PKGDIR) linux-amd64
	$(RM) $(PKGDIR).deb $(DOWNLOAD)

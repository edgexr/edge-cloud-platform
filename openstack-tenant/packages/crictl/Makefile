PACKAGE = crictl
VERSION = 1.16.1
SHA256SUM = 19fed421710fccfe58f5573383bb137c19438a9056355556f1a15da8d23b3ad1

DISTRIBUTION = cirrus
COMPONENT = main

PKGURL = https://github.com/kubernetes-sigs/cri-tools/releases/download/v$(VERSION)/crictl-v$(VERSION)-linux-amd64.tar.gz
DOWNLOAD = crictl.tar.gz

PKGDIR = $(PACKAGE)_$(VERSION)

all: setup_files
	../build.sh $(PACKAGE) $(VERSION) $(DISTRIBUTION) $(COMPONENT)

setup_files:
	mkdir $(PKGDIR)
	mkdir -p $(PKGDIR)/usr/local/bin
	wget -O $(DOWNLOAD) $(PKGURL)
	test `sha256sum $(DOWNLOAD) | awk '{print $$1}'` == $(SHA256SUM)
	tar xf $(DOWNLOAD) crictl
	mv crictl $(PKGDIR)/usr/local/bin/crictl
	chmod a+x $(PKGDIR)/usr/local/bin/crictl

clean:
	$(RM) -r $(PKGDIR)
	$(RM) $(PKGDIR).deb $(DOWNLOAD)

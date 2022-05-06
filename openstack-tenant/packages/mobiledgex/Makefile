PACKAGE = mobiledgex
VERSION = 4.10.0
DISTRIBUTION = cirrus
COMPONENT = main

PKGDIR = $(PACKAGE)_$(VERSION)

all: build-vers package

build-vers:
	mkdir -p ../../../version
	(cd ../../../version; ../openstack-tenant/packages/mobiledgex/version.sh "$(VERSION)")

package: builddir setup_files
	../build.sh $(PACKAGE) $(VERSION) $(DISTRIBUTION) $(COMPONENT)

builddir:
	mkdir $(PKGDIR)

$(PKGDIR)/etc/mobiledgex/% $(PKGDIR)/usr/local/bin/%: %
	mkdir -p $(dir $@)
	cp $< $@
	chmod a+x $@

$(PKGDIR)/etc/systemd/system/%: %
	mkdir -p $(dir $@)
	cp $< $@

setup_files: \
	$(PKGDIR)/etc/mobiledgex/install-k8s-master.sh \
	$(PKGDIR)/etc/mobiledgex/install-k8s-node.sh \
	$(PKGDIR)/etc/mobiledgex/cleanup-vm.sh \
	$(PKGDIR)/etc/mobiledgex/get-flavor.sh \
	$(PKGDIR)/etc/mobiledgex/setup-chef.sh \
	$(PKGDIR)/etc/mobiledgex/install-gpu-driver.sh \
	$(PKGDIR)/etc/systemd/system/mobiledgex.service \
	$(PKGDIR)/usr/local/bin/mobiledgex-init.sh

clean:
	$(RM) -r $(PKGDIR)
	$(RM) $(PKGDIR).deb

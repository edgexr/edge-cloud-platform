
all: build 

linux: build-linux

build:
	make -C ./openstack-tenant/agent/

build-linux:
	make -C ./openstack-tenant/agent/ linux

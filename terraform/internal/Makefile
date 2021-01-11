ANSIBLE_ROOT		= ../../../ansible
INIT_DONE_FLAG		= .terraform.init.done
TFWRAP			= ../tfwrap

all:
	@echo "make plan  : List changes that would be made"
	@echo "make deploy: Deploy the platform components"

init: $(INIT_DONE_FLAG)

$(INIT_DONE_FLAG): $(wildcard *.tf)
	$(TFWRAP) init
	touch $(INIT_DONE_FLAG)

plan: init
	$(TFWRAP) plan

deploy: init
	terraform apply

clean:
	$(RM) $(INIT_DONE_FLAG)

FORCE:

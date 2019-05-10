TFVARS		= ansible.auto.tfvars
ANSIBLE_VAULT	= ../../../ansible/ansible-mex-vault.yml
INIT_DONE_FLAG	= .terraform.init.done

all:
	@echo "make plan  : List changes that would be made"
	@echo "make deploy: Deploy the platform components"

$(TFVARS): $(ANSIBLE_VAULT)
	ansible-vault view $< | yq . >$@.tmp
	mv $@.tmp $@

init: $(INIT_DONE_FLAG)

$(INIT_DONE_FLAG): $(wildcard *.tf)
	terraform init
	touch $(INIT_DONE_FLAG)

plan: $(TFVARS) init
	terraform plan

deploy: $(TFVARS) init
	terraform apply

clean:
	$(RM) $(TFVARS) $(INIT)

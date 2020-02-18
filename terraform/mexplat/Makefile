ANSIBLE_ROOT		= ../../../ansible
ANSIBLE_TFVARS		= ansible.auto.tfvars
INIT_DONE_FLAG		= .terraform.init.done

all:
	@echo "make plan  : List changes that would be made"
	@echo "make deploy: Deploy the platform components"

$(ANSIBLE_TFVARS): FORCE
	cd $(ANSIBLE_ROOT); \
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES \
		ansible-playbook -i $(ANSIBLE_INVENTORY) \
			 -e @ansible-mex-vault-$(ANSIBLE_INVENTORY).yml \
			 -e "output_file=$(CURDIR)/ansible.auto.tfvars" \
			 mexplat-terraform-vars.yml

init: $(INIT_DONE_FLAG)

$(INIT_DONE_FLAG): $(wildcard *.tf)
	terraform init
	touch $(INIT_DONE_FLAG)

plan: $(ANSIBLE_TFVARS) init
	terraform plan

deploy: $(ANSIBLE_TFVARS) init
	terraform apply

clean:
	$(RM) $(ANSIBLE_TFVARS) $(INIT)

FORCE:

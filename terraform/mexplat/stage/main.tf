provider "azurerm" {
	version = "=1.24.0"

	client_id				= "${var.azure_terraform_service_principal_id}"
	client_secret		= "${var.azure_terraform_service_principal_secret}"
	subscription_id	= "${var.azure_subscription_id}"
	tenant_id				= "${var.azure_tenant_id}"

}

provider "google" {
	version = "=2.5.1"

	project	= "${var.gcp_project}"
	zone		= "${var.gcp_zone}"
}

terraform {
	backend "azurerm" {
		storage_account_name	= "mexterraformstate"
		container_name				= "mexplat-tfstate"
		key										= "stage.tfstate"
	}
}

module "k8s" {
	source							= "../../modules/k8s_azure"

	location						= "${var.azure_location}"
	client_id						= "${var.azure_terraform_service_principal_id}"
	client_secret				= "${var.azure_terraform_service_principal_secret}"
	cluster_name				= "${var.cluster_name}"
	vm_size							= "${var.azure_vm_size}"
	cluster_tag					= "mexplat-${var.environ_tag}"
	resource_group_name	= "${var.resource_group_name}"
}

# Common VM for gitlab, crm, mc, vault, postgres
module "gitlab" {
	source							= "../../modules/vm_gcp"

	instance_name				= "${var.gitlab_instance_name}"
	zone								= "${var.gcp_zone}"
	tags								= [ "mexplat-${var.environ_tag}", "gitlab-registry", "http-server", "https-server", "crm", "mc", "stun-turn" ]
}

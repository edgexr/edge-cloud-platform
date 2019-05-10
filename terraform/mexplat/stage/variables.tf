variable "environ_tag" {
	description	= "Name to tag instances created by this workspace"
	default			= "stage"
}

variable "azure_location" {
	description	= "Name of the Azure resource group for the cluster"
	default 		= "West US 2"
}

variable "azure_terraform_service_principal_id" {
	description	= "Azure service principal client ID"
	type				= "string"
}

variable "azure_terraform_service_principal_secret" {
	description	= "Azure service principal client secret"
	type				= "string"
}

variable "azure_subscription_id" {
	description	= "Azure subscription ID"
	type				= "string"
}

variable "azure_tenant_id" {
	description	= "Azure tenant ID"
	type				= "string"
}

variable "cluster_name" {
	default			= "mexplat-stage"
}

variable "resource_group_name" {
	default			= "mexplat-stage-rg"
}

variable "azure_vm_size" {
	default			= "Standard_DS1_v2"
}

variable "gcp_project" {
	default			= "still-entity-201400"
}

variable "gcp_zone" {
	default			= "us-west2-a"
}

variable "gitlab_instance_name" {
	default			= "gitlab-stage"
}

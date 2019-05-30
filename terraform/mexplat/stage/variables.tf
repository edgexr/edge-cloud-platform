variable "environ_tag" {
  description = "Name to tag instances created by this workspace"
  default     = "stage"
}

variable "azure_location" {
  description = "Name of the Azure resource group for the cluster"
  default     = "West US 2"
}

variable "azure_eu_location" {
  description = "Name of the Azure resource group for the EU cluster"
  default     = "West Europe"
}

variable "azure_terraform_service_principal_id" {
  description = "Azure service principal client ID"
  type        = "string"
}

variable "azure_terraform_service_principal_secret" {
  description = "Azure service principal client secret"
  type        = "string"
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = "string"
}

variable "azure_tenant_id" {
  description = "Azure tenant ID"
  type        = "string"
}

variable "cloudflare_account_email" {
  description = "Cloudflare account email"
  type        = "string"
}

variable "cloudflare_account_api_token" {
  description = "Cloudflare account API token"
  type        = "string"
}

variable "cluster_name" {
  default     = "mexplat-stage"
}

variable "eu_cluster_name" {
  default     = "mexplat-stage-eu"
}

variable "resource_group_name" {
  default     = "mexplat-stage-rg"
}

variable "eu_resource_group_name" {
  default     = "mexplat-stage-eu-rg"
}

variable "azure_vm_size" {
  default     = "Standard_DS1_v2"
}

variable "gcp_project" {
  default     = "still-entity-201400"
}

variable "gcp_zone" {
  default     = "us-west2-a"
}

variable "gitlab_instance_name" {
  default     = "gitlab-stage"
}

variable "console_instance_name" {
  default     = "console-stage"
}

// DNS entries

variable "crm_vm_domain_name" {
  description = "CRM VM domain name"
  type        = "string"
}

variable "mc_vm_domain_name" {
  description = "MC VM domain name"
  type        = "string"
}

variable "postgres_domain_name" {
  description = "Postgres domain name"
  type        = "string"
}

variable "gitlab_domain_name" {
  description = "Gitlab domain name"
  type        = "string"
}

variable "gitlab_docker_domain_name" {
  description = "Gitlab docker repo domain name"
  type        = "string"
}

variable "console_domain_name" {
  description = "Console domain name"
  type        = "string"
}

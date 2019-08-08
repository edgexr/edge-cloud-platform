variable "environ_tag" {
  description = "Name to tag instances created by this workspace"
  default     = "qa"
}

variable "azure_location" {
  description = "Name of the Azure resource group for the cluster"
  default     = "West US 2"
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
  default     = "mexplat-qa"
}

variable "resource_group_name" {
  default     = "mexplat-qa-rg"
}

variable "address_space" {
  default     = "172.30.0.0/24"
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
  default     = "gitlab-qa"
}

variable "console_instance_name" {
  default     = "console-qa"
}

// DNS entries

variable "vault_vm_domain_name" {
  description = "Vault domain name"
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

variable "ssh_public_key_file" {
  description = "SSH public key file for the ansible account"
  type        = "string"
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}

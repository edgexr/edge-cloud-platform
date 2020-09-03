variable "environ_tag" {
  description = "Name to tag instances created by this workspace"
  default     = "main"
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

variable "resource_group_name" {
  default     = "mexplat-main-rg"
}

variable "gcp_project" {
  default     = "still-entity-201400"
}

variable "gcp_zone" {
  default     = "us-west2-a"
}

variable "vault_vm_name" {
  default     = "vault-main"
}

variable "vault_domain_name" {
  default     = "vault-main.mobiledgex.net"
}

variable "vault_a_vm_name" {
  default     = "vault-main-a"
}

variable "vault_a_gcp_zone" {
  default     = "us-central1-a"
}

variable "vault_a_domain_name" {
  default     = "vault-main-a.mobiledgex.net"
}

variable "vault_b_vm_name" {
  default     = "vault-main-b"
}

variable "vault_b_gcp_zone" {
  default     = "europe-west3-a"
}

variable "vault_b_domain_name" {
  default     = "vault-main-b.mobiledgex.net"
}

variable "console_instance_name" {
  default     = "console-main"
}

variable "console_domain_name" {
  description = "Console domain name"
  type        = "string"
}

variable "console_vnc_domain_name" {
  description = "Console VNC domain name"
  type        = "string"
}

variable "alertmanager_domain_name" {
  default     = "alertmanager.mobiledgex.net"
}

variable "notifyroot_domain_name" {
  description = "Notifyroot service domain name"
  type        = "string"
}

variable "ssh_public_key_file" {
  description = "SSH public key file for the ansible account"
  type        = "string"
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}

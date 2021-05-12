variable "environ_tag" {
  description = "Name to tag instances created by this workspace"
  default     = "main"
}

variable "azure_terraform_service_principal_id" {
  description = "Azure service principal client ID"
  type        = string
}

variable "azure_terraform_service_principal_secret" {
  description = "Azure service principal client secret"
  type        = string
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "azure_tenant_id" {
  description = "Azure tenant ID"
  type        = string
}

variable "cloudflare_account_email" {
  description = "Cloudflare account email"
  type        = string
}

variable "cloudflare_account_api_token" {
  description = "Cloudflare account API token"
  type        = string
}

variable "resource_group_name" {
  default = "mexplat-main-rg"
}

variable "gcp_project" {
  default = "still-entity-201400"
}

variable "gcp_zone" {
  default = "us-west2-a"
}

variable "gitlab_instance_name" {
  default = "gitlab-main"
}

variable "gitlab_gcp_zone" {
  default = "us-west1-b"
}

variable "vault_vm_name" {
  default = "vault-main"
}

variable "vault_domain_name" {
  default = "vault-main.mobiledgex.net"
}

variable "vault_a_vm_name" {
  default = "vault-main-a"
}

variable "vault_a_gcp_zone" {
  default = "us-central1-a"
}

variable "vault_a_domain_name" {
  default = "vault-main-a.mobiledgex.net"
}

variable "vault_b_vm_name" {
  default = "vault-main-b"
}

variable "vault_b_gcp_zone" {
  default = "europe-west3-a"
}

variable "vault_b_domain_name" {
  default = "vault-main-b.mobiledgex.net"
}

variable "vault_c_vm_name" {
  default     = "vault-main-c"
}

variable "vault_c_gcp_zone" {
  default     = "asia-east1-b"
}

variable "vault_c_domain_name" {
  default     = "vault-main-c.mobiledgex.net"
}

variable "console_instance_name" {
  default = "console-main"
}

variable "console_domain_name" {
  description = "Console domain name"
  default     = "console"
}

variable "console_vnc_domain_name" {
  description = "Console VNC domain name"
  default     = "console-vnc.mobiledgex.net"
}

variable "alertmanager_domain_name" {
  default = "alertmanager.mobiledgex.net"
}

variable "notifyroot_domain_name" {
  description = "Notifyroot service domain name"
  default     = "notifyroot.mobiledgex.net"
}

variable "stun_domain_name" {
  description = "STUN service domain name"
  default     = "stun"
}

variable "harbor_static_address_name" {
  description = "Harbor static IP entity name"
  default     = "harbor"
}

variable "harbor_instance_name" {
  description = "Harbor registry instance name"
  default     = "harbor"
}

variable "harbor_domain_name" {
  description = "Harbor registry domain name"
  default     = "harbor.mobiledgex.net"
}

variable "ssh_public_key_file" {
  description = "SSH public key file for the ansible account"
  type        = string
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}


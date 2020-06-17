variable "environ_tag" {
  description = "Name to tag instances created by this workspace"
  default     = "tef"
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
  default			= "mobiledgex.ops@mobiledgex.com"
}

variable "cloudflare_account_api_token" {
  description = "Cloudflare account API token"
  type        = "string"
}

variable "resource_group_name" {
  default     = "mexplat-tef-rg"
}

variable "gitlab_instance_name" {
  default     = "gitlab-tef"
}

variable "gcp_project" {
  default     = "still-entity-201400"
}

variable "gcp_zone" {
  default     = "us-west2-a"
}

variable "postgres_domain_name" {
  description = "Postgres domain name"
	default			= "postgres-tef.mobiledgex.net"
}

variable "gitlab_domain_name" {
  description = "Gitlab domain name"
	default			= "gitlab-tef.mobiledgex.net"
}

variable "gitlab_docker_domain_name" {
  description = "Gitlab docker repo domain name"
	default			= "docker-tef.mobiledgex.net"
}

variable "crm_vm_domain_name" {
  description = "CRM VM domain name"
	default			= "crm-tef.mobiledgex.net"
}

variable "vault_vm_name" {
  default     = "vault-tef"
}

variable "vault_domain_name" {
  default     = "vault-tef.mobiledgex.net"
}

variable "vault_a_vm_name" {
  default     = "vault-tef-a"
}

variable "vault_a_gcp_zone" {
  default     = "us-central1-a"
}

variable "vault_a_domain_name" {
  default     = "vault-tef-a.mobiledgex.net"
}

variable "vault_b_vm_name" {
  default     = "vault-tef-b"
}

variable "vault_b_gcp_zone" {
  default     = "europe-west1-c"
}

variable "vault_b_domain_name" {
  default     = "vault-tef-b.mobiledgex.net"
}

variable "console_instance_name" {
  default     = "console-tef"
}

variable "console_domain_name" {
  description = "Console domain name"
	default			= "console-tef.mobiledgex.net"
}

variable "console_vnc_domain_name" {
  description = "Console VNC domain name"
	default			= "console-tef-vnc.mobiledgex.net"
}

variable "notifyroot_domain_name" {
  description = "Notifyroot service domain name"
	default			= "notifyroot-tef.mobiledgex.net"
}

variable "jaeger_instance_name" {
  default     = "jaeger-tef"
}

variable "jaeger_domain_name" {
  default     = "jaeger-tef.mobiledgex.net"
}

variable "ssh_public_key_file" {
  description = "SSH public key file for the ansible account"
  type        = "string"
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}

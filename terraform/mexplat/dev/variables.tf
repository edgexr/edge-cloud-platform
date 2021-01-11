variable "environ_tag" {
  description = "Name to tag instances created by this workspace"
  default     = "dev"
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

variable "azure_vm_size" {
  default = "Standard_DS1_v2"
}

variable "gcp_project" {
  default = "still-entity-201400"
}

variable "gcp_zone" {
  default = "us-west2-a"
}

variable "gitlab_instance_name" {
  default = "gitlab-dev"
}

variable "console_instance_name" {
  default = "console-dev"
}

variable "vault_b_instance_name" {
  default = "vault-dev-b"
}

variable "vault_b_gcp_zone" {
  default = "europe-west3-a"
}

// DNS entries

variable "crm_vm_domain_name" {
  description = "CRM VM domain name"
	default			= "crm-dev.mobiledgex.net"
}

variable "postgres_domain_name" {
  description = "Postgres domain name"
	default     = "postgres-dev.mobiledgex.net"
}

variable "gitlab_domain_name" {
  description = "Gitlab domain name"
	default     = "gitlab-dev.mobiledgex.net"
}

variable "gitlab_docker_domain_name" {
  description = "Gitlab docker repo domain name"
	default     = "docker-dev.mobiledgex.net"
}

variable "console_domain_name" {
  description = "Console domain name"
	default     = "console-dev.mobiledgex.net"
}

variable "console_vnc_domain_name" {
  description = "Console VNC domain name"
	default     = "console-dev-vnc.mobiledgex.net"
}

variable "notifyroot_domain_name" {
  description = "Notifyroot service domain name"
	default     = "notifyroot-dev.mobiledgex.net"
}

variable "jaeger_domain_name" {
  default = "jaeger-dev.mobiledgex.net"
}

variable "esproxy_domain_name" {
  default = "events-dev.es.mobiledgex.net"
}

variable "alertmanager_domain_name" {
  default = "alertmanager-dev"
}

variable "vault_a_domain_name" {
  default = "vault-dev-a.mobiledgex.net"
}

variable "vault_b_domain_name" {
  default = "vault-dev-b.mobiledgex.net"
}

variable "vault_c_domain_name" {
  default     = "vault-dev-c.mobiledgex.net"
}

variable "ssh_public_key_file" {
  description = "SSH public key file for the ansible account"
  type        = string
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}


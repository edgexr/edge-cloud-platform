variable "environ_tag" {
  description = "Name to tag instances created by this workspace"
  default     = "stage"
}

variable "azure_location" {
  description = "Azure location for the US cluster"
  default     = "West US 2"
}

variable "azure_eu_location" {
  description = "Azure location for the EU cluster"
  default     = "West Europe"
}

variable "azure_kr_location" {
  description = "Azure location for the KR cluster"
  default     = "Korea Central"
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
  default = "gitlab-stage"
}

variable "console_instance_name" {
  default = "console-stage"
}

variable "vault_b_instance_name" {
  default = "vault-stage-b"
}

variable "vault_b_gcp_zone" {
  default = "europe-west3-a"
}

// DNS entries

variable "crm_vm_domain_name" {
  description = "CRM VM domain name"
  default     = "crm-stage.mobiledgex.net"
}

variable "vault_vm_domain_name" {
  description = "Vault domain name"
  default     = "vault-stage.mobiledgex.net"
}

variable "postgres_domain_name" {
  description = "Postgres domain name"
  default     = "postgres-stage.mobiledgex.net"
}

variable "gitlab_domain_name" {
  description = "Gitlab domain name"
  default     = "gitlab-stage.mobiledgex.net"
}

variable "gitlab_docker_domain_name" {
  description = "Gitlab docker repo domain name"
  default     = "docker-stage.mobiledgex.net"
}

variable "console_domain_name" {
  description = "Console domain name"
  default     = "console-stage.mobiledgex.net"
}

variable "console_vnc_domain_name" {
  description = "Console VNC domain name"
  default     = "console-stage-vnc.mobiledgex.net"
}

variable "notifyroot_domain_name" {
  description = "Notifyroot service domain name"
  default     = "notifyroot-stage.mobiledgex.net"
}

variable "jaeger_domain_name" {
  default = "jaeger-stage.mobiledgex.net"
}

variable "esproxy_domain_name" {
  default = "events-stage.es.mobiledgex.net"
}

variable "alertmanager_domain_name" {
  default = "alertmanager-stage.mobiledgex.net"
}

variable "vault_a_domain_name" {
  default = "vault-stage-a.mobiledgex.net"
}

variable "vault_b_domain_name" {
  default = "vault-stage-b.mobiledgex.net"
}

variable "vault_c_domain_name" {
  default     = "vault-stage-c.mobiledgex.net"
}

variable "ssh_public_key_file" {
  description = "SSH public key file for the ansible account"
  type        = string
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}


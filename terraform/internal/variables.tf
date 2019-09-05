variable "environ_tag" {
  description = "Name to tag instances created by this workspace"
  default     = "internal"
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
  default     = "mexint-rg"
}

variable "gcp_project" {
  default     = "still-entity-201400"
}

variable "gcp_zone" {
  default     = "us-central1-b"
}

variable "influxdb_instance_name" {
  default     = "influxdb-internal"
}

variable "influxdb_vm_hostname" {
  description = "InfluxDB VM domain name"
  type        = "string"
}

variable "vouch_domain_name" {
  default     = "vouch.mobiledgex.net"
}

variable "jaeger_instance_name" {
  default     = "jaeger"
}

variable "jaeger_gcp_zone" {
  default     = "us-central1-a"
}

variable "jaeger_domain_name" {
  default     = "jaeger.mobiledgex.net"
}

variable "ssh_public_key_file" {
  description = "SSH public key file for the ansible account"
  type        = "string"
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}

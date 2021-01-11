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
  default = "mexint-rg"
}

variable "gcp_project" {
  default = "still-entity-201400"
}

variable "gcp_zone" {
  default = "us-central1-b"
}

variable "influxdb_instance_name" {
  default = "influxdb-internal"
}

variable "influxdb_vm_hostname" {
  description = "InfluxDB VM domain name"
  type        = string
  default     = "influxdb.internal.mobiledgex.net"
}

variable "vouch_domain_name" {
  default = "vouch.mobiledgex.net"
}

variable "jaeger_instance_name" {
  default = "jaeger"
}

variable "jaeger_gcp_zone" {
  default = "us-central1-a"
}

variable "jaeger_domain_name" {
  default = "jaeger.mobiledgex.net"
}

variable "esproxy_domain_name" {
  default = "events.es.mobiledgex.net"
}

variable "infra_domain_name" {
  default = "infra.internal.mobiledgex.net"
}

variable "infra_instance_name" {
  default = "infra-internal"
}

variable "apt_domain_name" {
  default = "apt.mobiledgex.net"
}

variable "apt_instance_name" {
  default = "apt"
}

variable "backups_domain_name" {
  default = "backups.mobiledgex.net"
}

variable "backups_instance_name" {
  default = "backups"
}

variable "chef_domain_name" {
  default = "chef"
}

variable "chef_instance_name" {
  default = "chef-master"
}

variable "chef_zone" {
  default = "us-central1-a"
}

variable "monitor_domain_name" {
  default = "monitor.mobiledgex.net"
}

variable "monitor_instance_name" {
  default = "monitor"
}

variable "monitor_zone" {
  default = "us-central1-a"
}

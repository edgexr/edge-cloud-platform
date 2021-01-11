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

variable "gcp_project" {
  default = "still-entity-201400"
}

variable "gcp_zone" {
  default = "us-west2-a"
}


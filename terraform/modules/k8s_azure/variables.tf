variable "client_id" {
  description = "The Azure service principal client ID"
  type        = "string"
  default     = "6f824eec-bcd8-4baa-8535-80747b1d41f7"
}

variable "client_secret" {
  description = "The Azure service principal client secret"
  type        = "string"
}

variable cluster_name {
  description = "Name of the cluster"
  type        = "string"
}

variable dns_prefix {
  description = "DNS prefix"
  type        = "string"
}

variable resource_group_name {
  description = "Name of the Azure resource group for the cluster"
  type        = "string"
}

variable location {
  description = "Azure location name for the cluster"
  type        = "string"
}

variable "agent_count" {
  description = "Number of nodes in the cluster"
  type        = "string"
  default     = 3
}

variable "vm_size" {
  description = "Azure VM size code"
  type        = "string"
}

variable "cluster_tag" {
  description = "Tag to associate with the cluster"
  type        = "string"
}

variable "ssh_public_key" {
  description = "SSH authorized key for admin account"
  type        = "string"
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}

variable "agent_pool_name" {
  description = "Name of the agent pool profile"
  type        = "string"
  default     = "agentpool"
}

variable "admin_username" {
  description = "Admin account username"
  type        = "string"
  default     = "ubuntu"
}

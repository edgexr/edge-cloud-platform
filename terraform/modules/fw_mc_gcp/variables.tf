variable "environ_tag" {
  description = "Environment the module belongs to"
  type        = string
}

variable "gitlab_ip" {
  description = "Gitlab IP"
  type        = string
}

variable "mc_federation_source_ranges" {
  description = "Source CIDRs for MC federation service"
  default     = [ "0.0.0.0/0" ]
}

variable "mc_federation_port" {
  description = "MC federation service port"
  default     = "30001"
}

variable "mc_ldap_port" {
  description = "MC LDAP service port"
  default     = "9389"
}

variable "mc_notify_port" {
  description = "MC notify service port"
  default     = "52001"
}

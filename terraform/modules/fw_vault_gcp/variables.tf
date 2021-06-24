variable "firewall_name" {
  description = "Name of the firewall"
  type        = string
}

variable "firewall_network" {
  description = "Name of the firewall network"
  default     = "default"
}

variable "target_tag" {
  description = "Target tag for the firewall"
  type        = string
}

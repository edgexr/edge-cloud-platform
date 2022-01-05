variable "environ_tag" {
  description = "Environment the module belongs to"
  type        = string
}

variable "teleport_proxy_source_ip" {
  description = "Source IP of the teleport proxy"
  default     = "146.148.73.170"
}

variable "teleport_node_ports" {
  description = "Port for the teleport node service"
  default     = [ "3022" ]
}

variable "environ_tag" {
  description = "Environment the module belongs to"
  type        = string
}

variable "console_ip" {
  description = "Console IP"
  type        = string
}

variable "postgres_port" {
  description = "Postgres service port"
  default     = "5432"
}

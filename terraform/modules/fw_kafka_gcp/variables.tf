variable "environ_tag" {
  description = "Environment the module belongs to"
  type        = string
}

variable "console_ip" {
  description = "Console IP"
  type        = string
}

variable "kafka_ports" {
  description = "Kafka ports"
  default     = ["9092", "9093"]
}

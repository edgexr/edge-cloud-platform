variable "environ_tag" {
  description = "Setup the VM instance belongs to"
}

variable "instance_name" {
  description = "VM instance name"
  type        = "string"
}

variable "instance_size" {
  description = "VM instance size"
  type        = "string"
  default     = "n1-standard-2"
}

variable "tags" {
  description = "Tags for VM instance"
  type        = "list"
}

variable "labels" {
  description = "Labels for VM instance"
  type        = "map"
  default     = {}
}

variable "zone" {
  description = "GCP zone for VM instance"
  type        = "string"
}

variable "boot_image" {
  description = "OS image"
  type        = "string"
  default     = "ubuntu-os-cloud/ubuntu-1804-lts"
}

variable "boot_disk_size" {
  description = "Boot disk size in GB"
  default     = 10
}

variable "allow_stopping_for_update" {
  description = "Flag to determine if the VM can be stopped for updates"
  default     = true
}

variable "deletion_protection" {
  description = "Flag to determine if the VM is delete-protected"
  default     = true
}

variable "network" {
  description = "Network for the VM instance"
  type        = "string"
  default     = "default"
}

variable "ansible_ssh_user" {
  description = "User account for ansible"
  type        = "string"
  default     = "ansible"
}

variable "instance_name" {
  description = "VM instance name"
  type        = "string"
}

variable "instance_size" {
  description = "VM instance size"
  type        = "string"
  default     = "Standard_DS1_v2"
}

variable "location" {
  description = "Azure resource location"
  type        = "string"
}

variable "resource_group_name" {
  description = "Name of the Azure resource group"
  type        = "string"
}

variable "virtual_network_address_space" {
  description = "Virtual network address space"
}

variable "subnet_address_prefix" {
  description = "Subnet address prefix"
}

variable "environ_tag" {
  description = "Environment identifier to substitute in component names"
  type        = "string"
}

variable "boot_image" {
  description = "OS image"
  type        = "map"

  default     = {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
  }
}

variable "deletion_protection" {
  description = "Flag to determine if the VM is delete-protected"
  default     = true
}

variable "ansible_ssh_user" {
  description = "User account for ansible"
  type        = "string"
  default     = "ansible"
}

variable "ssh_public_key_file" {
  description = "SSH public key file for the ansible account"
  type        = "string"
  default     = "~/.mobiledgex/id_rsa_mex.pub"
}

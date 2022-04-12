/**
 * Copyright 2022 MobiledgeX, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

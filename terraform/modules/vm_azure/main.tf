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

resource "azurerm_resource_group" "vm" {
  name                = "${var.resource_group_name}"
  location            = "${var.location}"
}

resource "azurerm_virtual_network" "vm" {
  name                = "${var.environ_tag}-network"
  location            = "${var.location}"
  address_space       = [ "${var.virtual_network_address_space}" ]
  resource_group_name = "${azurerm_resource_group.vm.name}"
}

resource "azurerm_subnet" "vm" {
  name                = "${var.environ_tag}-subnet"
  resource_group_name = "${azurerm_resource_group.vm.name}"
  virtual_network_name  = "${azurerm_virtual_network.vm.name}"
  address_prefix        = "${var.subnet_address_prefix}"
}

resource "azurerm_public_ip" "vm" {
  name                  = "${var.instance_name}-publicip"
  location            = "${var.location}"
  resource_group_name = "${azurerm_resource_group.vm.name}"
  allocation_method   = "Dynamic"
}

resource "azurerm_network_interface" "vm" {
  name                = "${var.instance_name}-intf"
  location            = "${var.location}"
  resource_group_name = "${azurerm_resource_group.vm.name}"

  ip_configuration {
    name              = "${var.instance_name}-ipconfig"
    subnet_id         = "${azurerm_subnet.vm.id}"
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = "${azurerm_public_ip.vm.id}"
  }
}

resource "azurerm_virtual_machine" "vm" {
  name                = "${var.instance_name}"
  location            = "${var.location}"
  resource_group_name = "${azurerm_resource_group.vm.name}"
  network_interface_ids = ["${azurerm_network_interface.vm.id}"]
  vm_size               = "${var.instance_size}"

  storage_image_reference {
    publisher           = "${var.boot_image["publisher"]}"
    offer               = "${var.boot_image["offer"]}"
    sku                 = "${var.boot_image["sku"]}"
    version             = "latest"
  }

  storage_os_disk {
    name                = "${var.instance_name}-disk"
    caching             = "ReadWrite"
    create_option       = "FromImage"
    managed_disk_type   = "Standard_LRS"
  }

  os_profile {
    computer_name       = "${var.instance_name}"
    admin_username      = "${var.ansible_ssh_user}"
  }

  os_profile_linux_config {
    disable_password_authentication = true
    ssh_keys                        = [{
      path      = "/home/${var.ansible_ssh_user}/.ssh/authorized_keys"
      key_data  = "${file(pathexpand(var.ssh_public_key_file))}"
    }]
  }
}

/*
resource "azurerm_management_lock" "vm" {
  name          = "${var.instance_name}-lock"
  scope         = "${azurerm_virtual_machine.vm.id}"
  lock_level    = "CanNotDelete"
}
*/

data "azurerm_public_ip" "vm" {
  name                = "${azurerm_public_ip.vm.name}"
  resource_group_name = "${azurerm_resource_group.vm.name}"
}

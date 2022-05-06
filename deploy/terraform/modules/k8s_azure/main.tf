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

resource "azurerm_resource_group" "k8s" {
  name      = "${var.resource_group_name}"
  location  = "${var.location}"
}

resource "azurerm_kubernetes_cluster" "k8s" {
  name                = "${var.cluster_name}"
  location            = "${azurerm_resource_group.k8s.location}"
  resource_group_name = "${azurerm_resource_group.k8s.name}"
  dns_prefix          = "${var.dns_prefix}"

  linux_profile {
    admin_username    = "${var.admin_username}"

    ssh_key {
      key_data        = "${file("${var.ssh_public_key}")}"
    }
  }

  agent_pool_profile {
    name              = "${var.agent_pool_name}"
    count             = "${var.agent_count}"
    vm_size           = "${var.vm_size}"
    os_type           = "Linux"
  }

  service_principal {
    client_id         = "${var.client_id}"
    client_secret     = "${var.client_secret}"
  }

  tags = {
    Environment       = "${var.cluster_tag}"
  }
}

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

data "template_file" "user_data" {
  template = file("${path.module}/cloud-config.yaml")
  vars = {
    ansible_ssh_user = var.ansible_ssh_user
    environ_tag      = var.environ_tag
  }
}

resource "google_compute_instance" "vm" {
  name         = var.instance_name
  machine_type = var.instance_size
  zone         = var.zone
  tags         = var.tags
  labels       = var.labels

  allow_stopping_for_update = var.allow_stopping_for_update
  deletion_protection       = var.deletion_protection

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = var.boot_disk_size
    }
  }

  network_interface {
    network = var.network
    access_config {
      nat_ip = var.nat_ip
    }
  }

  metadata = {
    user-data = data.template_file.user_data.rendered
  }
}


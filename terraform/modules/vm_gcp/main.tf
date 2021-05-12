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


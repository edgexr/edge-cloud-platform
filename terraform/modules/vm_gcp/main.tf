resource "google_compute_instance" vm {
	name					= "${var.instance_name}"
	machine_type	= "${var.instance_size}"
	zone					= "${var.zone}"
	tags					= "${var.tags}"

	allow_stopping_for_update	= "${var.allow_stopping_for_update}"
	deletion_protection				= "${var.deletion_protection}"

	boot_disk {
		initialize_params {
			image			= "${var.boot_image}"
		}
	}

	network_interface {
		network			= "${var.network}"
		access_config {
			// Ephemeral IP
		}
	}

	metadata {
		sshKeys			= "${var.ansible_ssh_user}:${file(pathexpand(var.ssh_public_key_file))}"
	}
}

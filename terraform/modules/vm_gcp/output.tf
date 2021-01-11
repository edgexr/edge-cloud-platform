output "external_ip" {
  value = google_compute_instance.vm.network_interface[0].access_config[0].nat_ip
}

output "zone" {
  value = google_compute_instance.vm.zone
}


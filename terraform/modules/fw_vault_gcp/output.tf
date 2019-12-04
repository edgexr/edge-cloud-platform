output "firewall_name" {
  value = "${google_compute_firewall.fw.name}"
}

output "firewall_network" {
  value = "${google_compute_firewall.fw.network}"
}

output "target_tag" {
  value = "${var.target_tag}"
}

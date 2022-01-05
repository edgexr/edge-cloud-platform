resource "google_compute_firewall" "teleport_node" {
  name    = "teleport-node-${var.environ_tag}"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = var.teleport_node_ports
  }

  target_tags = ["teleport-node-${var.environ_tag}"]
  source_ranges = [
    "${var.teleport_proxy_source_ip}/32",
  ]
}

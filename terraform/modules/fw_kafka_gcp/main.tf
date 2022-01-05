resource "google_compute_firewall" "kafka" {
  name    = "kafka-${var.environ_tag}"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = var.kafka_ports
  }

  target_tags = ["kafka-${var.environ_tag}"]
  source_ranges = [
    "${var.console_ip}/32",
  ]
}

resource "google_compute_firewall" "postgres" {
  name    = "postgres-${var.environ_tag}"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = [var.postgres_port]
  }

  target_tags = ["postgres-${var.environ_tag}"]
  source_ranges = [
    "${var.console_ip}/32",
  ]
}

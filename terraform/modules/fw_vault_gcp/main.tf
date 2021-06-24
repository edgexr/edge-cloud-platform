resource "google_compute_firewall" fw {
  name          = var.firewall_name
  network       = var.firewall_network

  allow {
    protocol    = "tcp"
    ports       = [ "8200" ]
  }

  target_tags   = [ var.target_tag ]
  source_ranges = [
    "130.211.0.0/22",
    "35.191.0.0/16"
  ]
}

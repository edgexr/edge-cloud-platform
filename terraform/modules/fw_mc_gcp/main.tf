resource "google_compute_firewall" "mc_federation" {
  name    = "mc-federation-${var.environ_tag}"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = [var.mc_federation_port]
  }

  target_tags = ["mc-federation-${var.environ_tag}"]
  source_ranges = var.mc_federation_source_ranges
}

resource "google_compute_firewall" "mc_ldap" {
  name    = "mc-ldap-${var.environ_tag}"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = [var.mc_ldap_port]
  }

  target_tags = ["mc-ldap-${var.environ_tag}"]
  source_ranges = [
    "${var.gitlab_ip}/32",
  ]
}

resource "google_compute_firewall" "mc_notify" {
  name    = "mc-notify-${var.environ_tag}"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = [var.mc_notify_port]
  }

  target_tags = ["mc-notify-${var.environ_tag}"]
  source_ranges = [
    "0.0.0.0/0",
  ]
}

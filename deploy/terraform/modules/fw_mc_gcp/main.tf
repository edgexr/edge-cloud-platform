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

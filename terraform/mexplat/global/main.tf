provider "azurerm" {
  version = "~> 2.96"

  client_id       = var.azure_terraform_service_principal_id
  client_secret   = var.azure_terraform_service_principal_secret
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
}

provider "google" {
  version = "~> 4.10"

  project = var.gcp_project
  zone    = var.gcp_zone
}

terraform {
  backend "azurerm" {
    storage_account_name = "mexterraformstate"
    container_name       = "mexplat-tfstate"
    key                  = "global.tfstate"
  }
}

# Firewall rules allowing Artifactory main and QA to talk to MC LDAP
resource "google_compute_firewall" "mc_artifactory" {
  name        = "mc-artifactory"
  description = "Artifactory main and QA access to MC LDAP"
  network     = "default"

  allow {
    protocol = "tcp"
    ports    = ["9389"]
  }

  target_tags = ["mc-artifactory"]
  source_ranges = [
    "35.233.222.88/32",
    "35.222.133.62/32",
  ]
}

# Firewall rules for Gitlab registry access
resource "google_compute_firewall" "vault" {
  name        = "vault-ac"
  description = "Vault API and cluster ports"
  network     = "default"

  allow {
    protocol = "tcp"
    ports    = ["8200", "8201"]
  }

  target_tags   = ["vault-ac"]
  source_ranges = ["0.0.0.0/0"]
}

# Firewall rules for Alertmanager access
resource "google_compute_firewall" "alertmanager" {
  name        = "alertmanager"
  description = "Alertmanager port"
  network     = "default"

  allow {
    protocol = "tcp"
    ports    = ["9094"]
  }

  target_tags   = ["alertmanager"]
  source_ranges = ["0.0.0.0/0"]
}

# Firewall rules for Notifyroot access
resource "google_compute_firewall" "notifyroot" {
  name        = "notifyroot"
  description = "Notifyroot port"
  network     = "default"

  allow {
    protocol = "tcp"
    ports    = ["53001"]
  }

  target_tags   = ["notifyroot"]
  source_ranges = ["0.0.0.0/0"]
}

# Firewall rules for STUN/TURN access
resource "google_compute_firewall" "stun_turn" {
  name        = "stun-turn"
  description = "STUN/TURN server"
  network     = "default"

  allow {
    protocol = "tcp"
    ports    = ["19302"]
  }

  allow {
    protocol = "udp"
    ports    = ["19302", "49160-49200"]
  }

  target_tags   = ["stun-turn"]
  source_ranges = ["0.0.0.0/0"]
}

# Firewall rule to restrict SSH access
resource "google_compute_firewall" "restricted_ssh" {
  name        = "restricted-ssh"
  description = "SSH access restricted"
  network     = "default"
  priority    = 1000

  deny {
    protocol = "tcp"
    ports    = ["22"]
  }

  target_tags   = ["restricted-ssh"]
  source_ranges = ["0.0.0.0/0"]
}

# Firewall rule to allow IAP access to SSH
resource "google_compute_firewall" "iap_ssh" {
  name        = "iap-ssh"
  description = "IAP access to SSH"
  network     = "default"
  priority    = 999

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  target_tags   = ["iap-ssh"]
  source_ranges = ["35.235.240.0/20"]
}

# IPs allowed direct SSH access to VMs
resource "google_compute_firewall" "restricted_ssh_overrides" {
  name        = "restricted-ssh-overrides"
  description = "List of IPs to allow direct SSH access to VMs with restricted SSH access. Primarily used for Ansible deployments."
  network     = "default"
  priority    = 998

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  target_tags   = ["restricted-ssh-overrides"]
  source_ranges = [
    "35.203.128.221/32",  # nightly.mobiledgex.net
    "40.122.108.233/32",  # jenkinsslave1
    "82.217.131.26/32",   # venky
    "47.186.99.201/32",   # leon
  ]
}

provider "azurerm" {
  version = "=1.24.0"

  client_id       = "${var.azure_terraform_service_principal_id}"
  client_secret   = "${var.azure_terraform_service_principal_secret}"
  subscription_id = "${var.azure_subscription_id}"
  tenant_id       = "${var.azure_tenant_id}"

}

provider "google" {
  version = "=2.5.1"

  project = "${var.gcp_project}"
  zone    = "${var.gcp_zone}"
}

terraform {
  backend "azurerm" {
    storage_account_name  = "mexterraformstate"
    container_name        = "mexplat-tfstate"
    key                   = "global.tfstate"
  }
}

# Firewall rules allowing Artifactory main and QA to talk to MC LDAP
resource "google_compute_firewall" mc_artifactory {
  name                    = "mc-artifactory"
  description             = "Artifactory main and QA access to MC LDAP"
  network                 = "default"

  allow {
    protocol              = "tcp"
    ports                 = [ "9389" ]
  }

  target_tags             = [ "mc-artifactory" ]
  source_ranges           = [
    "35.233.222.88/32",
    "35.222.133.62/32",
  ]
}

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

provider "cloudflare" {
  version = "=1.14.0"

  email   = "${var.cloudflare_account_email}"
  token   = "${var.cloudflare_account_api_token}"
}

terraform {
  backend "azurerm" {
    storage_account_name  = "mexterraformstate"
    container_name        = "mexplat-tfstate"
    key                   = "main.tfstate"
  }
}

# Vault VMs
module "vault_a" {
  source              = "../../modules/vm_gcp"

  instance_name       = "${var.vault_a_vm_name}"
  zone                = "${var.vault_a_gcp_zone}"
  boot_disk_size      = 20
  tags                = [
    "mexplat-${var.environ_tag}",
    "vault-ac",
    "${module.fw_vault_gcp.target_tag}"
  ]
  labels              = {
    "environ"         = "${var.environ_tag}",
    "vault"           = "true",
    "owner"           = "ops",
  }
  ssh_public_key_file = "${var.ssh_public_key_file}"
}

module "vault_a_dns" {
  source                        = "../../modules/cloudflare_record"
  hostname                      = "${var.vault_a_domain_name}"
  ip                            = "${module.vault_a.external_ip}"
}

module "vault_b" {
  source              = "../../modules/vm_gcp"

  instance_name       = "${var.vault_b_vm_name}"
  zone                = "${var.vault_b_gcp_zone}"
  boot_disk_size      = 20
  tags                = [
    "mexplat-${var.environ_tag}",
    "vault-ac",
    "${module.fw_vault_gcp.target_tag}"
  ]
  labels              = {
    "environ"         = "${var.environ_tag}",
    "vault"           = "true",
    "owner"           = "ops",
  }
  ssh_public_key_file = "${var.ssh_public_key_file}"
}

module "vault_b_dns" {
  source                        = "../../modules/cloudflare_record"
  hostname                      = "${var.vault_b_domain_name}"
  ip                            = "${module.vault_b.external_ip}"
}

# VM for console
module "console" {
  source              = "../../modules/vm_gcp"

  instance_name       = "${var.console_instance_name}"
  zone                = "${var.gcp_zone}"
  boot_disk_size      = 100
  tags                = [
    "http-server",
    "https-server",
    "console-debug",
    "mc-artifactory",
    "mc-ldap-${var.environ_tag}",
    "mc-notify-${var.environ_tag}",
    "notifyroot",
    "alertmanager",
  ]
  labels              = {
    "environ"         = "${var.environ_tag}",
    "console"         = "true",
    "owner"           = "ops",
  }
  ssh_public_key_file = "${var.ssh_public_key_file}"
}

module "console_dns" {
  source                        = "../../modules/cloudflare_record"
  hostname                      = "${var.console_domain_name}"
  ip                            = "${module.console.external_ip}"
}

module "console_vnc_dns" {
  source                        = "../../modules/cloudflare_record"
  hostname                      = "${var.console_vnc_domain_name}"
  ip                            = "${module.console.external_ip}"
}

module "alertmanager_dns" {
  source                        = "../../modules/cloudflare_record"
  hostname                      = "${var.alertmanager_domain_name}"
  ip                            = "${module.console.external_ip}"
}

module "notifyroot_dns" {
  source                        = "../../modules/cloudflare_record"
  hostname                      = "${var.notifyroot_domain_name}"
  ip                            = "${module.console.external_ip}"
}

module "fw_vault_gcp" {
  source                        = "../../modules/fw_vault_gcp"
  firewall_name                 = "${var.environ_tag}-vault-fw-hc-and-proxy"
  target_tag                    = "${var.environ_tag}-vault-hc-and-proxy"
}

resource "google_compute_firewall" mc_ldap {
  name                          = "mc-ldap-${var.environ_tag}"
  network                       = "default"

  allow {
    protocol                    = "tcp"
    ports                       = [ "9389" ]
  }

  target_tags                   = [ "mc-ldap-${var.environ_tag}" ]
  source_ranges                 = [
    "${module.gitlab.external_ip}/32"
  ]
}

resource "google_compute_firewall" mc_notify {
  name                          = "mc-notify-${var.environ_tag}"
  network                       = "default"

  allow {
    protocol                    = "tcp"
    ports                       = [ "52001" ]
  }

  target_tags                   = [ "mc-notify-${var.environ_tag}" ]
  source_ranges                 = [
    "0.0.0.0/0"
  ]
}

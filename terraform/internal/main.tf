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
    container_name        = "internal-tfstate"
    key                   = "internal.tfstate"
  }
}

module "influxdb" {
  source                  = "../modules/vm_gcp"

  instance_name           = "${var.influxdb_instance_name}"
  zone                    = "${var.gcp_zone}"
  boot_disk_size          = 100
  tags                    = [ "internal", "influxdb", "https-server" ]
  ssh_public_key_file     = "${var.ssh_public_key_file}"
}

module "influxdb_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.influxdb_vm_hostname}"
  ip                            = "${module.influxdb.external_ip}"
}

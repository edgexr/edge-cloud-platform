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

# Docker cache in West EU
module "docker_replica_west_eu" {
  source              = "../../modules/vm_gcp"

  instance_name       = "docker-replica-west-eu"
  zone                = "europe-west3-a"
  instance_size       = "custom-1-2816"
  boot_disk_size      = 10
  tags                = [ "mexplat-${var.environ_tag}", "http-server", "https-server" ]
}

module "docker_replica_west_eu_dns" {
  source                        = "../../modules/cloudflare_record"
  hostname                      = "docker-eu.mobiledgex.net"
  ip                            = "${module.docker_replica_west_eu.external_ip}"
}

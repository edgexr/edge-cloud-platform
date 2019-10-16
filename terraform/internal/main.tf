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
  instance_size           = "custom-1-4864"
  zone                    = "${var.gcp_zone}"
  boot_disk_size          = 100
  tags                    = [ "internal", "influxdb", "http-server", "https-server" ]
  ssh_public_key_file     = "${var.ssh_public_key_file}"
}

module "influxdb_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.influxdb_vm_hostname}"
  ip                            = "${module.influxdb.external_ip}"
}

module "vouch_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.vouch_domain_name}"
  ip                            = "${module.influxdb.external_ip}"
}

module "jaeger" {
  source                        = "../modules/vm_gcp"

  instance_name                 = "${var.jaeger_instance_name}"
  zone                          = "${var.jaeger_gcp_zone}"
  boot_disk_size                = 20
  tags                          = [ "mexplat-${var.environ_tag}", "http-server", "https-server", "jaeger" ]
  ssh_public_key_file           = "${var.ssh_public_key_file}"
}

module "jaeger_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.jaeger_domain_name}"
  ip                            = "${module.jaeger.external_ip}"
}

module "elasticsearch" {
  source                        = "../modules/vm_gcp"

  instance_name                = "${var.elasticsearch_instance_name}"
  zone                          = "${var.elasticsearch_gcp_zone}"
  boot_disk_size                = 200
  tags                          = [ "mexplat-${var.environ_tag}", "elasticsearch" ]
  ssh_public_key_file           = "${var.ssh_public_key_file}"
}

module "elasticsearch_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.elasticsearch_domain_name}"
  ip                            = "${module.elasticsearch.external_ip}"
}

module "kibana_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.kibana_domain_name}"
  ip                            = "${module.elasticsearch.external_ip}"
}

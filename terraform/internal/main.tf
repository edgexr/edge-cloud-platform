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
  tags                    = [ "internal", "influxdb", "http-server", "https-server", "mosh-default" ]
  labels                  = { "owner" = "venky" }
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
  labels                        = { "owner" = "ops" }
  ssh_public_key_file           = "${var.ssh_public_key_file}"
}

module "jaeger_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.jaeger_domain_name}"
  ip                            = "${module.jaeger.external_ip}"
}

module "esproxy_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.esproxy_domain_name}"
  ip                            = "${module.jaeger.external_ip}"
}

module "apt" {
  source                        = "../modules/vm_gcp"

  instance_name                 = "${var.apt_instance_name}"
  zone                          = "${var.gcp_zone}"
  boot_disk_size                = 1024
  tags                          = [ "mexplat-${var.environ_tag}", "infra", "http-server", "https-server" ]
  labels                        = { "owner" = "ops" }
  ssh_public_key_file           = "${var.ssh_public_key_file}"
}

module "apt_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.apt_domain_name}"
  ip                            = "${module.apt.external_ip}"
}

module "backups" {
  source                        = "../modules/vm_gcp"

  instance_name                 = "${var.backups_instance_name}"
  zone                          = "${var.gcp_zone}"
  boot_disk_size                = 1024
  tags                          = [ "mexplat-${var.environ_tag}", "infra", "docker-registry" ]
  labels                        = { "owner" = "ops" }
  ssh_public_key_file           = "${var.ssh_public_key_file}"
}

module "backups_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.backups_domain_name}"
  ip                            = "${module.backups.external_ip}"
}

module "chef" {
  source                        = "../modules/vm_gcp"

  instance_name                 = "${var.chef_instance_name}"
  instance_size                 = "n1-standard-2"
  zone                          = "${var.chef_zone}"
  boot_image                    = "ubuntu-1604-xenial-v20200407"
  boot_disk_size                = 100
  tags                          = [ "mexplat-${var.environ_tag}", "http-server", "https-server" ]
  labels                        = { "owner" = "ops" }
  ssh_public_key_file           = "${var.ssh_public_key_file}"
}

module "chef_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.chef_domain_name}"
  ip                            = "${module.chef.external_ip}"
}

module "monitor" {
  source                        = "../modules/vm_gcp"

  instance_name                 = "${var.monitor_instance_name}"
  instance_size                 = "n1-standard-2"
  zone                          = "${var.monitor_zone}"
  boot_disk_size                = 100
  tags                          = [ "mexplat-${var.environ_tag}", "http-server", "https-server" ]
  ssh_public_key_file           = "${var.ssh_public_key_file}"
}

module "monitor_dns" {
  source                        = "../modules/cloudflare_record"
  hostname                      = "${var.monitor_domain_name}"
  ip                            = "${module.monitor.external_ip}"
}

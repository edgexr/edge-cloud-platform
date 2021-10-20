provider "azurerm" {
  version = "~> 2.39.0"

  client_id       = var.azure_terraform_service_principal_id
  client_secret   = var.azure_terraform_service_principal_secret
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
}

provider "google" {
  version = "=2.5.1"

  project = var.gcp_project
  zone    = var.gcp_zone
}

provider "cloudflare" {
  version = "~> 2.14.0"

  email   = var.cloudflare_account_email
  api_key = var.cloudflare_account_api_token
}

provider "template" {
  version = "~> 2.2"
}

terraform {
  backend "azurerm" {
    storage_account_name = "mexterraformstate"
    container_name       = "internal-tfstate"
    key                  = "internal.tfstate"
  }
}

module "influxdb" {
  source = "../modules/vm_gcp"

  instance_name  = var.influxdb_instance_name
  environ_tag    = var.environ_tag
  instance_size  = "custom-1-4864"
  zone           = var.gcp_zone
  boot_disk_size = 100
  tags           = ["mexplat-internal", "influxdb", "http-server", "https-server", "mosh-default"]
  labels = {
    "owner" = "venky"
  }
}

module "influxdb_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.influxdb_vm_hostname
  ip       = module.influxdb.external_ip
}

module "vouch_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.vouch_domain_name
  ip       = module.influxdb.external_ip
}

module "jaeger" {
  source = "../modules/vm_gcp"

  instance_name  = var.jaeger_instance_name
  environ_tag    = var.environ_tag
  instance_size  = "custom-1-7680-ext"
  zone           = var.jaeger_gcp_zone
  boot_disk_size = 20
  tags           = ["mexplat-internal", "http-server", "https-server", "jaeger"]
  labels = {
    "owner" = "ops"
  }
}

module "jaeger_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.jaeger_domain_name
  ip       = module.jaeger.external_ip
}

module "esproxy_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.esproxy_domain_name
  ip       = module.jaeger.external_ip
}

module "apt" {
  source = "../modules/vm_gcp"

  instance_name  = var.apt_instance_name
  environ_tag    = var.environ_tag
  instance_size  = "custom-1-7680-ext"
  zone           = var.gcp_zone
  boot_disk_size = 1024
  tags           = [
		"mexplat-internal",
		"infra",
		"http-server",
		"https-server",
		"mosh-default"
	]
  labels = {
    "owner" = "ops"
  }
}

module "apt_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.apt_domain_name
  ip       = module.apt.external_ip
}

module "backups" {
  source = "../modules/vm_gcp"

  instance_name  = var.backups_instance_name
  environ_tag    = var.environ_tag
  zone           = var.gcp_zone
  boot_disk_size = 1024
  tags           = ["mexplat-internal", "infra", "docker-registry"]
  labels = {
    "owner" = "ops"
  }
}

module "backups_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.backups_domain_name
  ip       = module.backups.external_ip
}

module "chef" {
  source = "../modules/vm_gcp"

  instance_name  = var.chef_instance_name
  environ_tag    = var.environ_tag
  instance_size  = "n1-standard-4"
  zone           = var.chef_zone
  boot_image     = "ubuntu-1604-xenial-v20200407"
  boot_disk_size = 300
  tags           = ["mexplat-internal", "http-server", "https-server"]
  labels = {
    "owner" = "ops"
  }
}

module "chef_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.chef_domain_name
  ip       = module.chef.external_ip
}

module "monitor" {
  source = "../modules/vm_gcp"

  instance_name       = var.monitor_instance_name
  environ_tag         = var.environ_tag
  instance_size       = "custom-1-5376"
  zone                = var.monitor_zone
  boot_disk_size      = 100
  tags                = ["mexplat-internal", "http-server", "https-server"]
  labels = {
    "owner" = "venky"
  }
}

module "monitor_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.monitor_domain_name
  ip       = module.monitor.external_ip
}

module "openvas" {
  source = "../modules/vm_gcp"

  instance_name       = var.openvas_instance_name
  environ_tag         = var.environ_tag
  zone                = var.openvas_zone
  boot_image          = "ubuntu-os-cloud/ubuntu-2004-focal-v20210720"
  boot_disk_size      = 100
  tags                = ["mexplat-internal", "http-server", "https-server"]
  labels = {
    "owner" = "venky"
  }
}

module "openvas_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.openvas_domain_name
  ip       = module.openvas.external_ip
}

resource "google_compute_firewall" "teleport" {
  name = "teleport"
  description = "Teleport bastion"
  network = "default"

  allow {
    protocol = "tcp"
    ports = ["3023", "3024", "3025", "3026"]
  }

  target_tags = ["teleport"]
}

module "teleport" {
  source = "../modules/vm_gcp"

  instance_name       = var.teleport_instance_name
  environ_tag         = var.environ_tag
  zone                = var.teleport_zone
  boot_image          = "ubuntu-os-cloud/ubuntu-2004-lts"
  boot_disk_size      = 100
  tags                = [
    "mexplat-internal",
    "http-server",
    "https-server",
    "teleport",
  ]
  labels = {
    "owner" = "ops"
  }
}

module "teleport_dns" {
  source   = "../modules/cloudflare_record"
  hostname = var.teleport_domain_name
  ip       = module.teleport.external_ip
}

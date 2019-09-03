output "registry_replicas" {
  value = [
    {
      "location"  = "${module.docker_replica_west_eu.zone}"
      "hostname"  = "${module.docker_replica_west_eu_dns.hostname}"
      "ip"        = "${module.docker_replica_west_eu.external_ip}"
    }
  ]
}

output "vault_external_ip" {
  value = "${module.vault.external_ip}"
}

output "mc_external_ip" {
  value = "${module.mc.external_ip}"
}

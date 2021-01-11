output "gitlab_external_ip" {
  value = module.gitlab.external_ip
}

# Same as the Gitlab VM
output "crm_external_ip" {
  value = module.gitlab.external_ip
}

# Same as the Gitlab VM
output "postgres_external_ip" {
  value = module.gitlab.external_ip
}

output "console_external_ip" {
  value = module.console.external_ip
}


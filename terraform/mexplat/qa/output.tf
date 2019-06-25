output "gitlab_external_ip" {
  value = "${module.gitlab.external_ip}"
}

# Same as the Gitlab VM
output "vault_external_ip" {
  value = "${module.gitlab.external_ip}"
}

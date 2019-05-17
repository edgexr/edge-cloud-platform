output "kube_config" {
	value = "${module.k8s.kube_config}"
}

output "gitlab_external_ip" {
	value = "${module.gitlab.external_ip}"
}

# Same as the Gitlab VM
output "crm_external_ip" {
	value = "${module.gitlab.external_ip}"
}

# Same as the Gitlab VM
output "mc_external_ip" {
	value = "${module.gitlab.external_ip}"
}

# Same as the Gitlab VM
output "postgres_external_ip" {
	value = "${module.gitlab.external_ip}"
}

output "k8s_cluster_name" {
	value = "${var.cluster_name}"
}

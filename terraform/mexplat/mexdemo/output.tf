output "kube_config" {
  value = "${module.k8s.kube_config}"
}

output "k8s_cluster_name" {
  value = "${var.cluster_name}"
}

output "eu_kube_config" {
  value = "${module.k8s_eu.kube_config}"
}

output "eu_k8s_cluster_name" {
  value = "${var.eu_cluster_name}"
}

output "k8s_clusters" {
  value = [
    {
      "name" = "${var.cluster_name}"
      "kube_config" = "${module.k8s.kube_config}"
      "region" = "US"
    },
    {
      "name" = "${var.eu_cluster_name}"
      "kube_config" = "${module.k8s_eu.kube_config}"
      "region" = "EU"
    }
  ]
}

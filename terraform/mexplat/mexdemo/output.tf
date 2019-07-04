output "kube_config" {
  value = "${module.k8s.kube_config}"
}

output "k8s_cluster_name" {
  value = "${var.cluster_name}"
}

output "k8s_clusters" {
  value = [
    {
      "name" = "${var.cluster_name}"
      "kube_config" = "${module.k8s.kube_config}"
      "region" = "US"
    },
  ]
}

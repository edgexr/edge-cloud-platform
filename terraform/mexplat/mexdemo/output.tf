output "eu_kube_config" {
  value = "${module.k8s_eu.kube_config}"
}

output "eu_k8s_cluster_name" {
  value = "${var.eu_cluster_name}"
}

output "kr_kube_config" {
  value = "${module.k8s_kr.kube_config}"
}

output "kr_k8s_cluster_name" {
  value = "${var.kr_cluster_name}"
}

output "k8s_clusters" {
  value = [
    {
      "name" = "${var.kr_cluster_name}"
      "kube_config" = "${module.k8s_kr.kube_config}"
      "region" = "KR"
    },
    {
      "name" = "${var.eu_cluster_name}"
      "kube_config" = "${module.k8s_eu.kube_config}"
      "region" = "EU"
    },
  ]
}

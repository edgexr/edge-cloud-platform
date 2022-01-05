output "target_tag" {
  value = tolist(google_compute_firewall.teleport_node.target_tags)[0]
}

output "target_tag" {
  value = tolist(google_compute_firewall.postgres.target_tags)[0]
}

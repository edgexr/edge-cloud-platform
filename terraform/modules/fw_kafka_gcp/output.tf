output "target_tag" {
  value = tolist(google_compute_firewall.kafka.target_tags)[0]
}

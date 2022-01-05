output "target_tags" {
  value = concat(tolist(google_compute_firewall.mc_federation.target_tags),
                 tolist(google_compute_firewall.mc_ldap.target_tags),
                 tolist(google_compute_firewall.mc_notify.target_tags))
}

resource "cloudflare_record" vm {
  domain        = "${var.cloudflare_domain}"
  name          = "${var.hostname}"
  value         = "${var.ip}"
  type          = "A"
  ttl           = "${var.ttl}"
  proxied       = "${var.proxied}"
}

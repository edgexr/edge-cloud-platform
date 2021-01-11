resource "cloudflare_record" vm {
  zone_id       = "${var.cloudflare_zone_id}"
  name          = "${var.hostname}"
  value         = "${var.ip}"
  type          = "A"
  ttl           = "${var.ttl}"
  proxied       = "${var.proxied}"
}

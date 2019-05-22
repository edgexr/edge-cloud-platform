variable "cloudflare_domain" {
  description = "Cloudflare domain"
  default     = "mobiledgex.net"
}

variable "hostname" {
  description = "DNS record hostname"
  type        = "string"
}

variable "ip" {
  description = "DNS record IP"
  type        = "string"
}

variable "ttl" {
  description = "DNS record TTL"
  default     = "1"
}

variable "proxied" {
  description = "DNS is proxied through Cloudflare"
  default     = false
}

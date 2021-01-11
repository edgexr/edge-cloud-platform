variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID"
  default     = "7fcd588fdae300ac2ad0b519b0c0c8d8"
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

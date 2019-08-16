#!/bin/sh
set -e
if [ -z "$CF_USER" -o -z "$CF_APIKEY" ]; then
	echo "ERROR: Cloudflare credentials not provided" >&2
	exit 2
fi
cat >/etc/cloudflare.ini <<EOT
dns_cloudflare_email = $CF_USER
dns_cloudflare_api_key = $CF_APIKEY
EOT
chmod 400 /etc/cloudflare.ini
exec /usr/bin/supervisord -c /etc/supervisord.conf

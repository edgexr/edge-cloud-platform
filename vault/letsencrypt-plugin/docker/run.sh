#!/bin/sh
set -e
if [ -z "$CF_USER" -o -z "$CF_APIKEY" ]; then
	echo "ERROR: Cloudflare credentials not provided" >&2
	exit 2
fi
if [ -z "$NS1_APIKEY" ]; then
	echo "ERROR: NS1 api key not provided" >&2
	exit 2
fi
cat >/etc/cloudflare.ini <<EOT
dns_cloudflare_email = $CF_USER
dns_cloudflare_api_key = $CF_APIKEY
EOT
chmod 400 /etc/cloudflare.ini
cat >/etc/ns1.ini <<EOT
dns_nsone_api_key = $NS1_APIKEY
EOT
chmod 400 /etc/ns1.ini
exec /usr/bin/supervisord -c /etc/supervisord.conf

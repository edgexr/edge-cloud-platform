require 'bundler/setup'

require 'json'
require 'openssl'
require 'sinatra'

VALID_DOMAIN = ENV["DOMAIN"] || "mobiledgex.net"
OPS_EMAIL = ENV["OPS_EMAIL"] || "mobiledgex.ops@mobiledgex.com"
PRODUCTION = ENV["LETSENCRYPT_ENV"] == "production" ? true : false
LETSENCRYPT_DIR = "/etc/letsencrypt/live"

certbot = [
  "certbot", "certonly",
  "--non-interactive", "--agree-tos", "-m", OPS_EMAIL,
  "--dns-cloudflare", "--dns-cloudflare-credentials", "/etc/cloudflare.ini"
]
certbot << "--test-cert" unless PRODUCTION

get "/cert/:domain" do
  content_type :json

  domain = params[:domain]
  if not domain.end_with? VALID_DOMAIN
    status 401
    body "Invalid domain: #{domain}"
    return
  end

  certdir = File.join(LETSENCRYPT_DIR, domain)
  if not Dir.exist? certdir
    certbot_run = certbot + [ "-d", domain ]
    ok = system(*certbot_run)
    if not ok
      status 401
      body "Failed to generate cert: status = #{$?.exitstatus}"
      return
    end
  end

  cert = File.read File.join(certdir, "fullchain.pem")
  key = File.read File.join(certdir, "privkey.pem")

  x509 = OpenSSL::X509::Certificate.new cert
  ttl = (x509.not_after - Time.now).to_i

  cert = {
    :cert => cert,
    :key  => key,
    :ttl  => ttl,
  }
  cert.to_json
end

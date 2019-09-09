require 'bundler/setup'

require 'json'
require 'openssl'
require 'sinatra'

VALID_DOMAIN = ENV["DOMAIN"] || "mobiledgex.net"
NS1_DOMAINS = ENV["NS1_DOMAINS"] || "global.dme.mobiledgex.net"
OPS_EMAIL = ENV["OPS_EMAIL"] || "mobiledgex.ops@mobiledgex.com"
PRODUCTION = ENV["LETSENCRYPT_ENV"] == "production" ? true : false
LETSENCRYPT_DIR = "/etc/letsencrypt/live"

certbot = [
  "certbot", "certonly",
  "--non-interactive", "--agree-tos", "-m", OPS_EMAIL,
]
certbot << "--test-cert" unless PRODUCTION

dns_provider_args = {
  :cf => [ "--dns-cloudflare", "--dns-cloudflare-credentials", "/etc/cloudflare.ini" ],
  :ns1 => [ "--dns-nsone", "--dns-nsone-credentials", "/etc/ns1.ini" ]
}

ns1_domains = NS1_DOMAINS.split(',').map{|d| d.downcase}

get "/cert/:domain" do
  content_type :json

  domains = params[:domain].split(',').map{|d| d.downcase}.sort()

  ns1_list = []
  domains.each do |domain|
    if not domain.end_with? VALID_DOMAIN
      status 401
      body "Invalid domain: #{domain}"
      return
    end

    ns1_domains.each do |ns1_domain|
      if domain.end_with? ns1_domain
        ns1_list.push domain
        break
      end
    end
  end

  dns_provider = :cf
  if not ns1_list.empty?
    dns_provider = :ns1
    if ns1_list != domains
      status 401
      body "Cannot mix domains from different providers in same cert"
      return
    end
  end

  domain_list = domains.join(',')

  certdir = File.join(LETSENCRYPT_DIR, domain_list)
  if not Dir.exist? certdir
    certbot_run = certbot \
                    + dns_provider_args[dns_provider] \
                    + [ "--cert-name", domain_list ] \
                    + domains.map{|d| [ "-d", d ]}.flatten
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

# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'bundler/setup'

require 'json'
require 'open3'
require 'openssl'
require 'sinatra'

VALID_DOMAINS = ENV["DOMAINS"] || "mobiledgex.net"
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
valid_domains = VALID_DOMAINS.split(',').map{|d| d.downcase}

get "/cert/:domain" do
  content_type :json

  domains = params[:domain].split(',').map{|d| d.downcase}.sort()

  ns1_list = []
  domains.each do |domain|
    if not valid_domains.any? {|suffix| domain.end_with? suffix}
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

  domain_id = domains.join(',')

  # Replace wildcard requests starting with an '_.' with '*'
  domain_list = domains.map{|d| d.sub(/^_\./, '*.')}

  certdir = File.join(LETSENCRYPT_DIR, domain_id)
  if not Dir.exist? certdir
    certbot_run = certbot \
                    + dns_provider_args[dns_provider] \
                    + [ "--cert-name", domain_id ] \
                    + domain_list.map{|d| [ "-d", d ]}.flatten
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

get "/certs" do
  content_type :json
  certlist = `certbot certificates`
  re = Regexp.new('  Certificate Name: ([^\s]+)\n\s*Domains: ([^\s]+)\n\s*Expiry Date: ([^\s]+\s[^\s]+) \(([^\)]+)\)',
                  Regexp::MULTILINE)
  certs = {}
  certlist.scan(re).each do |cert|
    certs[cert[1]] = {
      :certname => cert[0],
      :valid_until => cert[2],
      :state => cert[3],
    }
  end

  certs.to_json
end

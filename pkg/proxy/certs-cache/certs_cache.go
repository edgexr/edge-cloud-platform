// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package certscache provides for issuing and caching of cloudlet
// rootLB certificates.
package certscache

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/access"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

const LETS_ENCRYPT_MAX_DOMAINS_PER_CERT = 100

const DefaultRefreshThreshold = 20 * 24 * time.Hour

var selfSignedCmd = `openssl req -new -newkey rsa:2048 -nodes -days 90 -nodes -x509 -config <(
cat <<-EOF
[req]
prompt = no
distinguished_name = dn

[ dn ]
CN = %s
EOF
)`

// Alt Names portion will look like:
// DNS.1 = test.com
// DNS.2 = matt.test.com
// ... going on for as many alternative names there are, and will be generated by getSelfSignedCerts
var selfSignedCmdWithSAN = `openssl req -new -newkey rsa:2048 -nodes -days 90 -nodes -x509 -config <(
cat <<-EOF
[req]
prompt = no
x509_extensions = v3_req
distinguished_name = dn

[ dn ]
CN = %s

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
%s
EOF
)`

var privKeyStart = "-----BEGIN PRIVATE KEY-----"
var privKeyEnd = "-----END PRIVATE KEY-----"
var certStart = "-----BEGIN CERTIFICATE-----"
var certEnd = "-----END CERTIFICATE-----"

type ProxyCertsCache struct {
	publicCertAPI    cloudcommon.GetPublicCertApi
	certsByCloudlet  map[edgeproto.CloudletKey]map[string]access.TLSCert
	mux              sync.Mutex
	refreshThreshold time.Duration
}

func NewProxyCertsCache(publicCertAPI cloudcommon.GetPublicCertApi) *ProxyCertsCache {
	return &ProxyCertsCache{
		publicCertAPI:    publicCertAPI,
		certsByCloudlet:  make(map[edgeproto.CloudletKey]map[string]access.TLSCert),
		refreshThreshold: DefaultRefreshThreshold,
	}
}

func GetWildcardName(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	parts[0] = "*"
	return strings.Join(parts, ".")
}

func (s *ProxyCertsCache) GetCert(ctx context.Context, key *edgeproto.CloudletKey, fqdn string, commercialCerts bool) (access.TLSCert, error) {
	// Convert fqdn to first label as wildcard. This allows all LBs in
	// a cloudlet to share the same cert.
	wildcardName := GetWildcardName(fqdn)

	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts get cert", "cloudlet", *key, "fqdn", fqdn, "wildcardName", wildcardName)

	// lookup existing cert
	s.mux.Lock()
	certs, ok := s.certsByCloudlet[*key]
	if !ok {
		certs = make(map[string]access.TLSCert)
		s.certsByCloudlet[*key] = certs
	}
	cert, ok := certs[wildcardName]
	s.mux.Unlock()

	if ok && time.Now().Before(cert.ExpiresAt) {
		return cert, nil
	}
	// create new cert
	tlscert, err := s.newCert(ctx, key, wildcardName, commercialCerts)
	if err != nil {
		return access.TLSCert{}, err
	}
	return tlscert, nil
}

func (s *ProxyCertsCache) newCert(ctx context.Context, key *edgeproto.CloudletKey, wildcardName string, commercialCerts bool) (access.TLSCert, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts new cert", "cloudlet", *key, "wildcardName", wildcardName, "commercialCerts", commercialCerts)
	var err error
	tls := access.TLSCert{}
	if commercialCerts {
		err = s.getCertFromVault(ctx, &tls, wildcardName)
	} else {
		err = getSelfSignedCerts(ctx, &tls, wildcardName)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to get new cert", "wildcardName", wildcardName, "err", err)
		return access.TLSCert{}, err
	}
	s.mux.Lock()
	certs, ok := s.certsByCloudlet[*key]
	if !ok {
		certs = make(map[string]access.TLSCert)
		s.certsByCloudlet[*key] = certs
	}
	certs[wildcardName] = tls
	s.mux.Unlock()

	return tls, nil
}

// RefreshCert returns the new cert and true if was refreshed
func (s *ProxyCertsCache) RefreshCert(ctx context.Context, key *edgeproto.CloudletKey, wildcardName string, commercialCerts bool) (access.TLSCert, bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCertsCache refresh cert", "wildcardName", wildcardName, "commercialCerts", commercialCerts)

	needsUpdate := true
	s.mux.Lock()
	certs, ok := s.certsByCloudlet[*key]
	if !ok {
		certs = make(map[string]access.TLSCert)
		s.certsByCloudlet[*key] = certs
	}
	cert, ok := certs[wildcardName]
	if ok && time.Until(cert.ExpiresAt) > s.refreshThreshold {
		needsUpdate = false
	}
	s.mux.Unlock()

	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts refresh check update needed", "wildcardName", wildcardName, "needsUpdate", needsUpdate)
	if !needsUpdate {
		return cert, false, nil
	}

	cert, err := s.newCert(ctx, key, wildcardName, commercialCerts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to create new cert for refresh", "wildcardName", wildcardName, "err", err)
		return cert, false, err
	}
	return cert, true, nil
}

func (s *ProxyCertsCache) RemoveUnused(ctx context.Context, key *edgeproto.CloudletKey, inUseWildcardNames map[string][]string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCertsCache flush expired certs", "cloudlet", *key)
	s.mux.Lock()
	defer s.mux.Unlock()
	certs, ok := s.certsByCloudlet[*key]
	if !ok {
		return
	}
	for wildcardName := range certs {
		if _, found := inUseWildcardNames[wildcardName]; found {
			continue
		}
		delete(certs, wildcardName)
	}
}

func (s *ProxyCertsCache) Count(key *edgeproto.CloudletKey) int {
	s.mux.Lock()
	defer s.mux.Unlock()
	certs, ok := s.certsByCloudlet[*key]
	if !ok {
		return 0
	}
	return len(certs)
}

func (s *ProxyCertsCache) Has(key *edgeproto.CloudletKey, wildcardName string) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	certs, ok := s.certsByCloudlet[*key]
	if !ok {
		return false
	}
	_, ok = certs[wildcardName]
	return ok
}

func (s *ProxyCertsCache) SetRefreshThreshold(refreshThreshold time.Duration) {
	s.refreshThreshold = refreshThreshold
}

// GetCertFromVault fills in the cert fields by calling the vault  plugin.  The vault plugin will
// return a new cert if one is not already available, or a cached copy of an existing cert.
func (s *ProxyCertsCache) getCertFromVault(ctx context.Context, tlsCert *access.TLSCert, commonNames ...string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCertFromVault", "commonNames", commonNames)
	// needs to have at least one domain name specified, and not more than LetsEncrypt's limit per cert
	// in reality len(commonNames) should always be 2, one for the sharedLB and a wildcard one for the dedicatedLBs
	if len(commonNames) < 1 || LETS_ENCRYPT_MAX_DOMAINS_PER_CERT < len(commonNames) {
		return fmt.Errorf("must have between 1 and %d domain names specified", LETS_ENCRYPT_MAX_DOMAINS_PER_CERT)
	}
	names := strings.Join(commonNames, ",")
	if s.publicCertAPI == nil {
		return fmt.Errorf("Access API is not initialized")
	}
	// vault API uses "_" to denote wildcard
	commonName := strings.Replace(names, "*", "_", 1)
	pubCert, err := s.publicCertAPI.GetPublicCert(ctx, commonName)
	if err != nil {
		return fmt.Errorf("Failed to get public cert from vault for commonName %s: %v", commonName, err)
	}
	if pubCert.Cert == "" {
		return fmt.Errorf("No cert found in cert from vault")
	}
	if pubCert.Key == "" {
		return fmt.Errorf("No key found in cert from vault")
	}
	expiresIn := time.Duration(pubCert.TTL) * time.Second

	tlsCert.ExpiresAt = time.Now().Add(expiresIn)
	tlsCert.CertString = pubCert.Cert
	tlsCert.KeyString = pubCert.Key
	tlsCert.TTL = pubCert.TTL
	tlsCert.CommonName = names
	return nil
}

// Generates a self signed cert for testing purposes or if crm does not have access to vault
func getSelfSignedCerts(ctx context.Context, tlsCert *access.TLSCert, commonNames ...string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Generating self-signed cert", "commonNames", commonNames)
	var args string
	if len(commonNames) < 1 {
		return fmt.Errorf("Must have at least one domain name specified for cert generation")
	} else if len(commonNames) == 1 {
		args = fmt.Sprintf(selfSignedCmd, commonNames[0])
	} else {
		altNames := []string{}
		for i, name := range commonNames {
			altNames = append(altNames, fmt.Sprintf("DNS.%d = %s", i+1, name))
		}
		args = fmt.Sprintf(selfSignedCmdWithSAN, commonNames[0], strings.Join(altNames, "\n"))
	}
	cmd := exec.Command("bash", "-c", args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error generating cert: %v\n", err)
	}
	output := string(out)
	tlsCert.ExpiresAt = time.Now().Add(90 * 24 * time.Hour)

	// Get the private key
	start := strings.Index(output, privKeyStart)
	end := strings.Index(output, privKeyEnd)
	if start == -1 || end == -1 {
		return fmt.Errorf("Cert generation failed, could not find start or end of private key")
	}
	end = end + len(privKeyEnd)
	tlsCert.KeyString = output[start:end]

	// Get the cert
	start = strings.Index(output, certStart)
	end = strings.Index(output, certEnd)
	if start == -1 || end == -1 {
		return fmt.Errorf("Cert generation failed, could not find start or end of private key")
	}
	end = end + len(certEnd)
	tlsCert.CertString = output[start:end]
	return nil
}

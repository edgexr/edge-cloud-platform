// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	mextls "github.com/edgexr/edge-cloud-platform/pkg/tls"
)

// Third party services that we deploy all have their own letsencrypt-public
// issued certificate, with a CA pool that includes the vault internal public CAs.
// This allows mTLS where the public node uses a public cert and our internal
// services use an internal vault pki cert.
// Examples of such services are Jaeger, ElasticSearch, etc.
func (s *NodeMgr) GetPublicClientTlsConfig(ctx context.Context) (*tls.Config, error) {
	if s.tlsClientIssuer == NoTlsClientIssuer {
		// unit test mode
		return nil, nil
	}
	tlsOpts := []TlsOp{
		WithPublicCAPool(),
	}
	if mextls.IsTestTls() {
		// skip verifying cert if e2e-tests, because cert
		// will be self-signed
		log.SpanLog(ctx, log.DebugLevelInfo, "public client tls e2e-test mode")
		tlsOpts = append(tlsOpts, WithTlsSkipVerify(true))
	}
	return s.InternalPki.GetClientTlsConfig(ctx,
		s.CommonNamePrefix(),
		s.tlsClientIssuer,
		[]MatchCA{},
		tlsOpts...)
}

var refreshDelay = 2 * time.Hour

type PubCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// PublicCertManager manages refreshing the public cert.
type PublicCertManager struct {
	commonNamePrefix    string
	tlsMode             mextls.TLSMode
	useGetPublicCertApi bool // denotes whether to use GetPublicCertApi to grab certs or use command line provided cert (should be equivalent to useVaultPki flag)
	getPublicCertApi    cloudcommon.GetPublicCertApi
	certs               map[string]*PubCert
	done                bool
	refreshTrigger      chan bool
	refreshThreshold    time.Duration
	validDomains        []string
	mux                 sync.Mutex
}

func NewPublicCertManager(commonNamePrefix, validDomains string, getPublicCertApi cloudcommon.GetPublicCertApi, tlsCertFile string, tlsKeyFile string) (*PublicCertManager, error) {
	// Nominally letsencrypt certs are valid for 90 days
	// and they recommend refreshing at 30 days to expiration.
	mgr := &PublicCertManager{
		commonNamePrefix: commonNamePrefix,
		refreshTrigger:   make(chan bool, 1),
		refreshThreshold: 30 * 24 * time.Hour,
		tlsMode:          mextls.ServerAuthTLS,
		validDomains:     strings.Split(validDomains, ","),
		certs:            make(map[string]*PubCert),
	}
	if len(mgr.validDomains) == 0 && commonNamePrefix != "localhost" {
		return nil, fmt.Errorf("no valid domains specified")
	}

	if getPublicCertApi != nil {
		mgr.useGetPublicCertApi = true
		mgr.getPublicCertApi = getPublicCertApi
	} else if tlsCertFile != "" && tlsKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
		if err != nil {
			return nil, err
		}
		for _, cn := range mgr.getCommonNames() {
			mgr.certs[cn] = &PubCert{
				cert: &cert,
			}
		}
	} else {
		// no tls
		mgr.tlsMode = mextls.NoTLS
	}
	return mgr, nil
}

func (s *PublicCertManager) getCommonNames() []string {
	if s.commonNamePrefix == "localhost" {
		// testing only
		return []string{s.commonNamePrefix}
	}
	cns := []string{}
	for _, domain := range s.validDomains {
		cns = append(cns, s.commonNamePrefix+"."+domain)
	}
	return cns
}

func (s *PublicCertManager) TLSMode() mextls.TLSMode {
	return s.tlsMode
}

func (s *PublicCertManager) updateCerts(ctx context.Context) error {
	if s.tlsMode == mextls.NoTLS || !s.useGetPublicCertApi {
		// If no tls or using command line certs, do not update
		return nil
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "update public certs", "prefix", s.commonNamePrefix, "domains", s.validDomains)
	for _, commonName := range s.getCommonNames() {
		vaultCert, err := s.getPublicCertApi.GetPublicCert(ctx, commonName)
		if err != nil {
			return err
		}
		expiresIn := time.Duration(vaultCert.TTL) * time.Second
		cert, err := tls.X509KeyPair([]byte(vaultCert.Cert), []byte(vaultCert.Key))
		if err != nil {
			return err
		}
		s.mux.Lock()
		pubcert := PubCert{
			cert:      &cert,
			expiresAt: time.Now().Add(expiresIn),
		}
		s.certs[commonName] = &pubcert
		log.SpanLog(ctx, log.DebugLevelInfo, "new cert", "name", commonName, "expiresIn", expiresIn, "expiresAt", pubcert.expiresAt)
		s.mux.Unlock()
	}
	return nil
}

// For now this just assumes server-side only TLS.
func (s *PublicCertManager) GetServerTlsConfig(ctx context.Context) (*tls.Config, error) {
	if s.tlsMode == mextls.NoTLS {
		// No tls
		return nil, nil
	}
	if len(s.certs) == 0 {
		// make sure we have cert
		err := s.updateCerts(ctx)
		if err != nil {
			return nil, err
		}
	}
	config := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.NoClientCert,
		GetCertificate: s.GetCertificateFunc(),
	}
	return config, nil
}

func (s *PublicCertManager) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		s.mux.Lock()
		defer s.mux.Unlock()
		if info.ServerName == "" {
			// no serverName specified, return first cert
			notFound := []string{}
			expired := []string{}
			for _, cn := range s.getCommonNames() {
				pubcert, ok := s.certs[cn]
				if !ok {
					notFound = append(notFound, cn)
					continue
				}
				if time.Now().After(pubcert.expiresAt) {
					expired = append(expired, cn)
					continue // expired
				}
				return pubcert.cert, nil
			}
			log.DebugLog(log.DebugLevelApi, "no valid cert found for tls client without serverName", "validNames", s.getCommonNames(), "notFound", notFound, "expired", expired)
		} else {
			// do substring match to allow for wild cards
			for cn, pubcert := range s.certs {
				if strings.HasSuffix(info.ServerName, cn) {
					return pubcert.cert, nil
				}
			}
			log.DebugLog(log.DebugLevelApi, "no cert found for tls client", "serverName", info.ServerName, "validNames", s.getCommonNames())
		}
		return nil, fmt.Errorf("no certificate found for serverName %q" + info.ServerName)
	}
}

func (s *PublicCertManager) StartRefresh() {
	s.done = false
	go func() {
		for {
			select {
			case <-time.After(refreshDelay):
			case <-s.refreshTrigger:
			}
			span := log.StartSpan(log.DebugLevelInfo, "check refresh public certs")
			ctx := log.ContextWithSpan(context.Background(), span)
			if s.done {
				log.SpanLog(ctx, log.DebugLevelInfo, "refresh public cert done")
				span.Finish()
				break
			}
			for _, commonName := range s.getCommonNames() {
				s.mux.Lock()
				pubcert, ok := s.certs[commonName]
				s.mux.Unlock()
				if !ok {
					continue
				}
				expiresIn := time.Until(pubcert.expiresAt)
				if expiresIn > s.refreshThreshold {
					continue
				}
				err := s.updateCerts(ctx)
				log.SpanLog(ctx, log.DebugLevelInfo, "refreshed cert", "commonName", commonName, "err", err)
			}
			span.Finish()
		}
	}()
}

func (s *PublicCertManager) StopRefresh() {
	s.done = true
	select {
	case s.refreshTrigger <- true:
	default:
	}
}

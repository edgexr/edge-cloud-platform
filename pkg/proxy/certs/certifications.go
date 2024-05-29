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

package certs

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/access"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
	opentracing "github.com/opentracing/opentracing-go"
)

const LETS_ENCRYPT_MAX_DOMAINS_PER_CERT = 100

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

var AtomicCertsUpdater = "/usr/local/bin/atomic-certs-update.sh"

var refreshThreshold = 20 * 24 * time.Hour

type RootLBAPI interface {
	// Get ssh clients of all root LBs
	GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error)
}

type ProxyCerts struct {
	cloudletKey           *edgeproto.CloudletKey
	rootLBAPI             RootLBAPI
	publicCertAPI         cloudcommon.GetPublicCertApi
	nodeMgr               *node.NodeMgr
	haMgr                 *redundancy.HighAvailabilityManager
	getRootLBCertsTrigger chan bool
	certs                 map[string]access.TLSCert
	mux                   sync.Mutex
	fixedCerts            bool
	commercialCerts       bool
	sudoType              pc.Sudo
	done                  bool
	envoyImage            string
}

func NewProxyCerts(ctx context.Context, key *edgeproto.CloudletKey, rootLBAPI RootLBAPI, publicCertAPI cloudcommon.GetPublicCertApi, nodeMgr *node.NodeMgr, haMgr *redundancy.HighAvailabilityManager, platformFeatures *edgeproto.PlatformFeatures, commercialCerts bool, envoyImage string) *ProxyCerts {
	sudoType := pc.SudoOn
	log.SpanLog(ctx, log.DebugLevelInfo, "ProxyCerts start")
	if platformFeatures.IsFake || platformFeatures.IsEdgebox || platformFeatures.CloudletServicesLocal {
		sudoType = pc.NoSudo
		if commercialCerts {
			// for devtest platforms, disable commercial certs
			log.SpanLog(ctx, log.DebugLevelInfo, "GetRootLbCerts, disable commercial certs for devtest platforms")
			commercialCerts = false
		}
	}
	fixedCerts := false
	if platformFeatures.IsFake {
		fixedCerts = true
	}
	return &ProxyCerts{
		cloudletKey:           key,
		rootLBAPI:             rootLBAPI,
		publicCertAPI:         publicCertAPI,
		nodeMgr:               nodeMgr,
		haMgr:                 haMgr,
		fixedCerts:            fixedCerts,
		commercialCerts:       commercialCerts,
		getRootLBCertsTrigger: make(chan bool),
		certs:                 make(map[string]access.TLSCert),
		sudoType:              sudoType,
		envoyImage:            envoyImage,
	}
}

// Start starts proxy cert refresh thread
func (s *ProxyCerts) Start(ctx context.Context) {
	go func() {
		for {
			lbCertsSpan := log.StartSpan(log.DebugLevelInfo, "get rootlb certs thread", opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
			err := s.refreshCerts(ctx)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "refresh certs failed", "err", err)
			}
			s.nodeMgr.Event(ctx, "refresh certs failed", s.cloudletKey.Organization, s.cloudletKey.GetTags(), err)
			lbCertsSpan.Finish()
			select {
			case <-time.After(1 * 24 * time.Hour):
			case <-s.getRootLBCertsTrigger:
			}
			if s.done {
				return
			}
		}
	}()
}

func (s *ProxyCerts) Stop() {
	s.done = true
	s.TriggerRootLBCertsRefresh()
}

func getWildcardName(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	parts[0] = "*"
	return strings.Join(parts, ".")
}

func (s *ProxyCerts) getCert(ctx context.Context, fqdn string) (access.TLSCert, error) {
	// Convert fqdn to first label as wildcard. This allows all LBs in
	// a cloudlet to share the same cert.
	wildcardName := getWildcardName(fqdn)

	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts get cert", "fqdn", fqdn, "wildcardName", wildcardName)

	// lookup existing cert
	s.mux.Lock()
	cert, ok := s.certs[wildcardName]
	s.mux.Unlock()
	// note that we shouldn't ever find expired certs as long as the
	// refresh thread is working.
	if ok && time.Now().Before(cert.ExpiresAt) {
		return cert, nil
	}
	// create new cert
	tlscert, err := s.newCert(ctx, wildcardName)
	if err != nil {
		return access.TLSCert{}, err
	}
	return tlscert, nil
}

func (s *ProxyCerts) newCert(ctx context.Context, wildcardName string) (access.TLSCert, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts new cert", "wildcardName", wildcardName)
	var err error
	tls := access.TLSCert{}
	if s.commercialCerts {
		err = s.getCertFromVault(ctx, &tls, wildcardName)
	} else {
		err = getSelfSignedCerts(ctx, &tls, wildcardName)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to get new cert", "wildcardName", wildcardName, "err", err)
		return access.TLSCert{}, err
	}
	s.mux.Lock()
	s.certs[wildcardName] = tls
	s.mux.Unlock()

	return tls, nil
}

func (s *ProxyCerts) refreshCerts(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts refresh certs")
	var err error
	if !s.haMgr.PlatformInstanceActive {
		log.SpanLog(ctx, log.DebugLevelInfra, "skipping lb certs update for standby CRM")
		return nil
	}

	lbClients, err := s.rootLBAPI.GetRootLBClients(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get dedicated RootLB ssh clients: %v", err)
	}
	wcToLBs := make(map[string][]string)
	for lbname, lbclient := range lbClients {
		wildcardName := getWildcardName(lbclient.FQDN)
		wcToLBs[wildcardName] = append(wcToLBs[wildcardName], lbname)
	}

	errs := []string{}
	refreshed := 0
	for wildcardName, lbNames := range wcToLBs {
		needsUpdate := true
		s.mux.Lock()
		cert, ok := s.certs[wildcardName]
		if ok && time.Until(cert.ExpiresAt) > refreshThreshold {
			needsUpdate = false
		}
		s.mux.Unlock()

		log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts refresh check update needed", "wildcardName", wildcardName, "lbNames", lbNames, "needsUpdate", needsUpdate)
		if !needsUpdate {
			continue
		}

		cert, err := s.newCert(ctx, wildcardName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to create new cert for refresh", "wildcardName", wildcardName, "err", err)
			errs = append(errs, err.Error())
			continue
		}
		refreshed++

		// apply new cert
		for _, lbname := range lbNames {
			lbClient := lbClients[lbname]
			err = s.writeCertToRootLb(ctx, &cert, lbClient.Client, lbname)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to write cert to lb", "wildcardName", wildcardName, "lbname", lbname, "err", err)
				errs = append(errs, err.Error())
			}
		}
	}

	// Clean up unused certs. Note there is a race condition here that
	// after we created wcToLBs another thread created a new LB and added
	// the cert before we run the clean up below. In that case, the cert will
	// be removed from the cache, but the next refresh will restore it.
	// This is not so bad because Vault also is caching certs, so we'll get
	// back a copy of the same cert as before.
	s.mux.Lock()
	removed := 0
	certsInCache := 0
	for wildcardName := range s.certs {
		if _, ok := wcToLBs[wildcardName]; !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts remove unused cert", "wildcardName", wildcardName)
			delete(s.certs, wildcardName)
			removed++
		}
	}
	certsInCache = len(s.certs)
	s.mux.Unlock()

	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts refresh certs done", "refreshed", refreshed, "removed", removed, "certsInCache", certsInCache, "loop-errors", errs)

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ", "))
	}
	return nil
}

func (s *ProxyCerts) writeCertToRootLb(ctx context.Context, tls *access.TLSCert, client ssh.Client, lbname string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "write proxy certs to rootLB", "lbname", lbname)
	out, err := client.Output("pwd")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Error: Unable to get pwd", "name", lbname, "err", err)
		return err
	}
	certsDir, certFile, keyFile := cloudcommon.GetCertsDirAndFiles(string(out))

	// write it to rootlb
	err = pc.Run(client, "mkdir -p "+certsDir)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "can't create cert dir on rootlb", "certDir", certsDir)
		return fmt.Errorf("failed to create cert dir on rootlb: %s, %v", certsDir, err)
	} else {
		if s.fixedCerts {
			// For testing, avoid atomic certs update as it will create timestamp based directories
			err = pc.WriteFile(client, certFile, tls.CertString, "tls cert", s.sudoType)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "unable to write tls cert file to rootlb", "err", err)
				return fmt.Errorf("failed to write tls cert file to rootlb, %v", err)
			}
			err = pc.WriteFile(client, keyFile, tls.KeyString, "tls key", s.sudoType)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "unable to write tls key file to rootlb", "err", err)
				return fmt.Errorf("failed to write tls cert file to rootlb, %v", err)
			}
			return nil
		}
		certsScript, err := ioutil.ReadFile(AtomicCertsUpdater)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to read atomic certs updater script", "err", err)
			return fmt.Errorf("failed to read atomic certs updater script: %v", err)
		}
		err = pc.WriteFile(client, AtomicCertsUpdater, string(certsScript), "atomic-certs-updater", s.sudoType)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to copy atomic certs updater script", "err", err)
			return fmt.Errorf("failed to copy atomic certs updater script: %v", err)
		}
		err = pc.WriteFile(client, certFile+".new", tls.CertString, "tls cert", s.sudoType)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to write tls cert file to rootlb", "err", err)
			return fmt.Errorf("failed to write tls cert file to rootlb, %v", err)
		}
		err = pc.WriteFile(client, keyFile+".new", tls.KeyString, "tls key", s.sudoType)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to write tls key file to rootlb", "err", err)
			return fmt.Errorf("failed to write tls cert file to rootlb, %v", err)
		}
		sudoString := ""
		if s.sudoType == pc.SudoOn {
			sudoString = "sudo "
		}
		tag := ""
		if atSign := strings.LastIndexByte(s.envoyImage, '@'); atSign > 0 {
			// sha256 tag uses '@'
			tag = s.envoyImage[atSign+1:]
		} else if colon := strings.LastIndexByte(s.envoyImage, ':'); colon > 0 {
			tag = s.envoyImage[colon+1:]
		}
		if tag == "" {
			return fmt.Errorf("could not get tag from envoy image %q", s.envoyImage)
		}
		err = pc.Run(client, fmt.Sprintf("%sbash %s -d %s -c %s -k %s -e %s", sudoString, AtomicCertsUpdater, certsDir, filepath.Base(certFile), filepath.Base(keyFile), tag))
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to write tls cert file to rootlb", "err", err)
			return fmt.Errorf("failed to atomically update tls certs: %v", err)
		}
	}
	return nil
}

// GetCertFromVault fills in the cert fields by calling the vault  plugin.  The vault plugin will
// return a new cert if one is not already available, or a cached copy of an existing cert.
func (s *ProxyCerts) getCertFromVault(ctx context.Context, tlsCert *access.TLSCert, commonNames ...string) error {
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

func (s *ProxyCerts) SetupTLSCerts(ctx context.Context, fqdn, lbname string, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupTLSCerts", "fqdn", fqdn, "lbname", lbname)

	cert, err := s.getCert(ctx, fqdn)
	if err != nil {
		return err
	}
	err = s.writeCertToRootLb(ctx, &cert, client, lbname)
	if err != nil {
		return err
	}
	return nil
}

func (s *ProxyCerts) TriggerRootLBCertsRefresh() {
	select {
	case s.getRootLBCertsTrigger <- true:
	default:
	}
}

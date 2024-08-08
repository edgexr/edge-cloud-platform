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
	"path/filepath"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/access"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
	opentracing "github.com/opentracing/opentracing-go"
)

var AtomicCertsUpdater = "/usr/local/bin/atomic-certs-update.sh"

type RootLBAPI interface {
	// Get ssh clients of all root LBs
	GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error)
}

type ProxyCerts struct {
	cloudletKey           *edgeproto.CloudletKey
	rootLBAPI             RootLBAPI
	nodeMgr               *node.NodeMgr
	haMgr                 *redundancy.HighAvailabilityManager
	getRootLBCertsTrigger chan bool
	cache                 *certscache.ProxyCertsCache
	fixedCerts            bool
	commercialCerts       bool
	sudoType              pc.Sudo
	done                  bool
	envoyImage            string
}

func NewProxyCerts(ctx context.Context, key *edgeproto.CloudletKey, rootLBAPI RootLBAPI, nodeMgr *node.NodeMgr, haMgr *redundancy.HighAvailabilityManager, platformFeatures *edgeproto.PlatformFeatures, commercialCerts bool, envoyImage string, cache *certscache.ProxyCertsCache) *ProxyCerts {
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
		nodeMgr:               nodeMgr,
		haMgr:                 haMgr,
		fixedCerts:            fixedCerts,
		commercialCerts:       commercialCerts,
		getRootLBCertsTrigger: make(chan bool),
		cache:                 cache,
		sudoType:              sudoType,
		envoyImage:            envoyImage,
	}
}

// Start starts proxy cert refresh thread
func (s *ProxyCerts) Start(ctx context.Context) {
	go func() {
		for {
			lbCertsSpan := log.StartSpan(log.DebugLevelInfo, "get rootlb certs thread", opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
			err := s.RefreshCerts(ctx)
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

func (s *ProxyCerts) RefreshCerts(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ProxyCerts refresh certs", "cloudlet", s.cloudletKey)
	var err error
	if s.haMgr != nil && !s.haMgr.PlatformInstanceActive {
		log.SpanLog(ctx, log.DebugLevelInfra, "skipping lb certs update for standby CRM")
		return nil
	}

	lbClients, err := s.rootLBAPI.GetRootLBClients(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get dedicated RootLB ssh clients: %v", err)
	}
	wcToLBs := make(map[string][]string)
	for lbname, lbclient := range lbClients {
		wildcardName := certscache.GetWildcardName(lbclient.FQDN)
		wcToLBs[wildcardName] = append(wcToLBs[wildcardName], lbname)
	}

	errs := []string{}
	for wildcardName, lbNames := range wcToLBs {
		cert, updated, err := s.cache.RefreshCert(ctx, s.cloudletKey, wildcardName, s.commercialCerts)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to refresh cert", "wildcardName", wildcardName, "err", err)
			errs = append(errs, err.Error())
			continue
		}
		if !updated {
			continue
		}

		// apply new cert
		for _, lbname := range lbNames {
			lbClient := lbClients[lbname]
			if lbClient.Client == nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "refreshCerts skipping unexpected nil client", "lbname", lbname, "fqdn", lbClient.FQDN)
				errs = append(errs, "no ssh client for "+lbname)
				continue
			}
			err = s.writeCertToRootLb(ctx, &cert, lbClient.Client, lbname)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to write cert to lb", "wildcardName", wildcardName, "lbname", lbname, "err", err)
				errs = append(errs, err.Error())
			}
		}
	}

	s.cache.RemoveUnused(ctx, s.cloudletKey, wcToLBs)

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

func (s *ProxyCerts) SetupTLSCerts(ctx context.Context, fqdn, lbname string, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupTLSCerts", "fqdn", fqdn, "lbname", lbname)

	cert, err := s.cache.GetCert(ctx, s.cloudletKey, fqdn, s.commercialCerts)
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

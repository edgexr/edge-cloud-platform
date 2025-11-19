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

package controller

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func (s *CloudletApi) InitVaultClient(ctx context.Context) error {
	s.vaultClient = accessapi.NewVaultClient(ctx, vaultConfig, s.all.cloudletNodeApi, s.all.cloudletIPsApi.cloudletIPs, *region, *dnsZone, nodeMgr.ValidDomains)
	return nil
}

// Issue certificate to RegionalCloudlet service.
func (s *CloudletApi) IssueCert(ctx context.Context, req *edgeproto.IssueCertRequest) (*edgeproto.IssueCertReply, error) {
	verified := svcnode.ContextGetAccessKeyVerified(ctx)
	if verified == nil {
		// should never reach here if it wasn't verified
		return nil, fmt.Errorf("Client authentication not verified")
	}
	certId := svcnode.CertId{
		CommonNamePrefix: req.CommonNamePrefix,
		CommonName:       req.CommonName,
		Issuer:           svcnode.CertIssuerRegionalCloudlet,
	}
	vaultCert, err := nodeMgr.InternalPki.IssueVaultCertDirect(ctx, certId)
	if err != nil {
		return nil, err
	}
	reply := &edgeproto.IssueCertReply{
		PublicCertPem: string(vaultCert.PublicCertPEM),
		PrivateKeyPem: string(vaultCert.PrivateKeyPEM),
	}
	return reply, nil
}

// Get CAs for RegionalCloudlet service. To match the Vault API,
// each request only returns one CA.
func (s *CloudletApi) GetCas(ctx context.Context, req *edgeproto.GetCasRequest) (*edgeproto.GetCasReply, error) {
	// Should be verified, but we don't really care because these are public certs
	cab, err := nodeMgr.InternalPki.GetVaultCAsDirect(ctx, req.Issuer)
	if err != nil {
		return nil, err
	}
	reply := &edgeproto.GetCasReply{
		CaChainPem: string(cab),
	}
	return reply, err
}

func (s *CloudletApi) UpgradeAccessKey(stream edgeproto.CloudletAccessKeyApi_UpgradeAccessKeyServer) error {
	ctx := stream.Context()
	log.SpanLog(ctx, log.DebugLevelApi, "upgrade access key")
	return s.accessKeyServer.UpgradeAccessKey(stream, s.commitAccessPublicKey)
}

func (s *CloudletApi) commitAccessPublicKey(ctx context.Context, key *edgeproto.CloudletKey, pubPEM string, haRole process.HARole) error {
	return s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cloudlet := edgeproto.Cloudlet{}
		if !s.store.STMGet(stm, key, &cloudlet) {
			// deleted
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelApi, "commit upgraded key")
		if haRole == process.HARoleSecondary {
			cloudlet.SecondaryCrmAccessPublicKey = pubPEM
			cloudlet.SecondaryCrmAccessKeyUpgradeRequired = false
		} else {
			cloudlet.CrmAccessPublicKey = pubPEM
			cloudlet.CrmAccessKeyUpgradeRequired = false
		}
		s.store.STMPut(stm, &cloudlet)
		return nil
	})
}

func (s *CloudletApi) GetAccessData(ctx context.Context, req *edgeproto.AccessDataRequest) (*edgeproto.AccessDataReply, error) {
	verified := svcnode.ContextGetAccessKeyVerified(ctx)
	if verified == nil {
		// should never reach here if it wasn't verified
		return nil, fmt.Errorf("Client authentication not verified")
	}
	cloudlet := &edgeproto.Cloudlet{}
	if !s.all.cloudletApi.cache.Get(&verified.Key, cloudlet) {
		return nil, verified.Key.NotFoundError()
	}
	vaultClient := s.vaultClient.CloudletContext(cloudlet)
	handler := accessapi.NewControllerHandler(cloudlet, vaultClient, s.all.cloudletIPsApi.cloudletIPs)
	return handler.GetAccessData(ctx, req)
}

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

package accessapi

import (
	"context"
	"encoding/json"

	"github.com/cloudflare/cloudflare-go"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

// ControllerClient implements platform.AccessApi for cloudlet
// services by connecting to the Controller.
// To avoid having to change the Controller's API if we need to
// add new functions to the platform.AccessApi interface, all
// requests to the Controller go through a generic single API.
// Data is marshaled here. Unmarshaling is done in ControllerHandler.
type ControllerClient struct {
	client edgeproto.CloudletAccessApiClient
}

func NewControllerClient(client edgeproto.CloudletAccessApiClient) *ControllerClient {
	return &ControllerClient{
		client: client,
	}
}

func (s *ControllerClient) GetCloudletAccessVars(ctx context.Context) (map[string]string, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetCloudletAccessVars,
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return nil, err
	}
	vars := map[string]string{}
	err = json.Unmarshal(reply.Data, &vars)
	return vars, err
}

func (s *ControllerClient) GetRegistryAuth(ctx context.Context, imgUrl string) (*cloudcommon.RegistryAuth, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetRegistryAuth,
		Data: []byte(imgUrl),
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return nil, err
	}
	auth := &cloudcommon.RegistryAuth{}
	err = json.Unmarshal(reply.Data, auth)
	return auth, err
}

func (s *ControllerClient) SignSSHKey(ctx context.Context, publicKey string) (string, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.SignSSHKey,
		Data: []byte(publicKey),
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return "", err
	}
	return string(reply.Data), nil
}

func (s *ControllerClient) GetSSHPublicKey(ctx context.Context) (string, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetSSHPublicKey,
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return "", err
	}
	return string(reply.Data), nil
}

func (s *ControllerClient) GetOldSSHKey(ctx context.Context) (*vault.MEXKey, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetOldSSHKey,
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return nil, err
	}
	mexKey := &vault.MEXKey{}
	err = json.Unmarshal(reply.Data, mexKey)
	return mexKey, err
}

func (s *ControllerClient) GetPublicCert(ctx context.Context, commonName string) (*vault.PublicCert, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetPublicCert,
		Data: []byte(commonName),
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return nil, err
	}
	pubcert := &vault.PublicCert{}
	err = json.Unmarshal(reply.Data, pubcert)
	return pubcert, err
}

func (s *ControllerClient) CreateOrUpdateDNSRecord(ctx context.Context, name, rtype, content string, ttl int, proxy bool) error {
	record := platform.DNSRequest{
		Name:    name,
		RType:   rtype,
		Content: content,
		TTL:     ttl,
		Proxy:   proxy,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	req := &edgeproto.AccessDataRequest{
		Type: platform.CreateOrUpdateDNSRecord,
		Data: data,
	}
	_, err = s.client.GetAccessData(ctx, req)
	return err
}

func (s *ControllerClient) GetDNSRecords(ctx context.Context, fqdn string) ([]cloudflare.DNSRecord, error) {
	record := platform.DNSRequest{
		Name: fqdn,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetDNSRecords,
		Data: data,
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return nil, err
	}
	records := make([]cloudflare.DNSRecord, 0)
	err = json.Unmarshal(reply.Data, &records)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (s *ControllerClient) DeleteDNSRecord(ctx context.Context, recordID string) error {
	record := platform.DNSRequest{
		Name: recordID,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	req := &edgeproto.AccessDataRequest{
		Type: platform.DeleteDNSRecord,
		Data: data,
	}
	_, err = s.client.GetAccessData(ctx, req)
	return err
}

func (s *ControllerClient) GetSessionTokens(ctx context.Context, secretName string) (string, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetSessionTokens,
		Data: []byte(secretName),
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return "", err
	}
	code := string(reply.Data)
	return code, nil
}

func (s *ControllerClient) GetKafkaCreds(ctx context.Context) (*node.KafkaCreds, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetKafkaCreds,
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return nil, err
	}
	creds := node.KafkaCreds{}
	err = json.Unmarshal(reply.Data, &creds)
	return &creds, err
}

func (s *ControllerClient) GetGCSCreds(ctx context.Context) ([]byte, error) {
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetGCSCreds,
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return nil, err
	}
	return reply.Data, err
}

func (s *ControllerClient) GetFederationAPIKey(ctx context.Context, fedKey *federationmgmt.FedKey) (*federationmgmt.ApiKey, error) {
	data, err := json.Marshal(fedKey)
	if err != nil {
		return nil, err
	}
	req := &edgeproto.AccessDataRequest{
		Type: platform.GetFederationAPIKey,
		Data: data,
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return nil, err
	}
	apiKey := federationmgmt.ApiKey{}
	err = json.Unmarshal(reply.Data, &apiKey)
	return &apiKey, err
}

func (s *ControllerClient) CreateCloudletNode(ctx context.Context, cloudletNode *edgeproto.CloudletNode) (string, error) {
	data, err := json.Marshal(cloudletNode)
	if err != nil {
		return "", err
	}
	req := &edgeproto.AccessDataRequest{
		Type: platform.CreateCloudletNode,
		Data: data,
	}
	reply, err := s.client.GetAccessData(ctx, req)
	if err != nil {
		return "", err
	}
	return string(reply.Data), err
}

func (s *ControllerClient) DeleteCloudletNode(ctx context.Context, key *edgeproto.CloudletNodeKey) error {
	data, err := json.Marshal(*key)
	if err != nil {
		return err
	}
	req := &edgeproto.AccessDataRequest{
		Type: platform.DeleteCloudletNode,
		Data: data,
	}
	_, err = s.client.GetAccessData(ctx, req)
	return err
}

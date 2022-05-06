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

package infracommon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
	"github.com/tmc/scp"
)

type CloudletSSHKey struct {
	PublicKey       string
	SignedPublicKey string
	PrivateKey      string
	Mux             sync.Mutex
	RefreshTrigger  chan bool

	// Below is used to upgrade old VMs to new Vault based SSH
	MEXPrivateKey    string
	UseMEXPrivateKey bool
}

var CloudletSSHKeyRefreshInterval = 24 * time.Hour

func SetCloudletSignedSSHKey(ctx context.Context, accessApi platform.AccessApi, sshKey *CloudletSSHKey) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Sign cloudlet public key from Vault")

	signedKey, err := accessApi.SignSSHKey(ctx, sshKey.PublicKey)
	if err != nil {
		return err
	}

	sshKey.Mux.Lock()
	defer sshKey.Mux.Unlock()
	sshKey.SignedPublicKey = signedKey

	return nil
}

func TriggerRefreshCloudletSSHKeys(sshKey *CloudletSSHKey) {
	select {
	case sshKey.RefreshTrigger <- true:
	default:
	}
}

func (cp *CommonPlatform) RefreshCloudletSSHKeys(accessApi platform.AccessApi) {
	interval := CloudletSSHKeyRefreshInterval
	for {
		select {
		case <-time.After(interval):
		case <-cp.SshKey.RefreshTrigger:
		}
		span := log.StartSpan(log.DebugLevelInfra, "refresh Cloudlet SSH Key")
		ctx := log.ContextWithSpan(context.Background(), span)
		err := SetCloudletSignedSSHKey(ctx, accessApi, &cp.SshKey)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "refresh cloudlet ssh key failure", "err", err)
			// retry again soon
			interval = time.Hour
		} else {
			interval = CloudletSSHKeyRefreshInterval
		}
		span.Finish()
	}
}

func (cp *CommonPlatform) InitCloudletSSHKeys(ctx context.Context, accessApi platform.AccessApi) error {
	// Generate Cloudlet SSH Keys
	log.SpanLog(ctx, log.DebugLevelInfra, "InitCloudletSSHKeys")
	cloudletPubKey, cloudletPrivKey, err := ssh.GenKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate cloudlet SSH key pair: %v", err)
	}
	cp.SshKey.PublicKey = cloudletPubKey
	cp.SshKey.PrivateKey = cloudletPrivKey
	err = SetCloudletSignedSSHKey(ctx, accessApi, &cp.SshKey)
	if err != nil {
		return err
	}
	cp.SshKey.RefreshTrigger = make(chan bool, 1)
	return nil
}

//GetSSHClientFromIPAddr returns ssh client handle for the given IP.
func (cp *CommonPlatform) GetSSHClientFromIPAddr(ctx context.Context, ipaddr string, ops ...pc.SSHClientOp) (ssh.Client, error) {
	opts := pc.SSHOptions{Timeout: DefaultConnectTimeout, User: SSHUser}
	opts.Apply(ops)
	var client ssh.Client
	var err error

	if cp.SshKey.PrivateKey == "" {
		return nil, fmt.Errorf("missing cloudlet private key")
	}
	if cp.SshKey.PrivateKey == "" {
		return nil, fmt.Errorf("missing cloudlet signed public Key")
	}

	cp.SshKey.Mux.Lock()
	auth := ssh.Auth{
		KeyPairs: []ssh.KeyPair{
			{
				PublicRawKey:  []byte(cp.SshKey.SignedPublicKey),
				PrivateRawKey: []byte(cp.SshKey.PrivateKey),
			},
		},
	}
	cp.SshKey.Mux.Unlock()

	if cp.SshKey.UseMEXPrivateKey {
		auth = ssh.Auth{RawKeys: [][]byte{
			[]byte(cp.SshKey.MEXPrivateKey),
		}}
	}
	gwhost, gwport := cp.Properties.GetCloudletCRMGatewayIPAndPort()
	if gwhost != "" {
		// start the client to GW and add the addr as next hop
		client, err = ssh.NewNativeClient(opts.User, ClientVersion, gwhost, gwport, &auth, opts.Timeout, nil)
		if err != nil {
			return nil, err
		}
		client, err = client.AddHop(ipaddr, 22)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		client, err = ssh.NewNativeClient(SSHUser, ClientVersion, ipaddr, 22, &auth, opts.Timeout, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot get ssh client for addr %s, %v", ipaddr, err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Created SSH Client", "ipaddr", ipaddr, "gwhost", gwhost, "timeout", opts.Timeout)
	return client, nil
}

func SCPFilePath(sshClient ssh.Client, srcPath, dstPath string) error {
	client, ok := sshClient.(*ssh.NativeClient)
	if !ok {
		return fmt.Errorf("unable to cast client to native client")
	}
	session, sessionInfo, err := client.Session(client.DefaultClientConfig.Timeout)
	if err != nil {
		return err
	}
	defer sessionInfo.CloseAll()
	err = scp.CopyPath(srcPath, dstPath, session)
	return err
}

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

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/tmc/scp"
)

// GetSSHClientFromIPAddr returns ssh client handle for the given IP.
func (cp *CommonPlatform) GetSSHClientFromIPAddr(ctx context.Context, ipaddr string, ops ...pc.SSHClientOp) (ssh.Client, error) {
	opts := pc.SSHOptions{Timeout: DefaultConnectTimeout, User: SSHUser}
	opts.Apply(ops)
	var client ssh.Client
	var err error

	if cp.PlatformConfig.CloudletSSHKey == nil {
		return nil, fmt.Errorf("cloudlet ssh key generator not provided")
	}

	auth := ssh.Auth{
		KeyPairsCallback: cp.PlatformConfig.CloudletSSHKey.GetKeyPairsCb(ctx),
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
		config, err := ssh.NewNativeConfig(SSHUser, ClientVersion, &auth, opts.Timeout, nil)
		if err != nil {
			return nil, err
		}
		client, err = ssh.NewNativeClientWithConfig(ipaddr, 22, config)
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

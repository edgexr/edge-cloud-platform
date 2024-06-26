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

package infracommon

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/test-go/testify/require"
)

// Test vault signed ssh
func TestVaultSSH(t *testing.T) {
	t.Skip("manual testing only")
	log.SetDebugLevel(log.DebugLevelApi | log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// set VAULT_TOKEN in env
	vaultConfig, err := vault.BestConfig(os.Getenv("VAULT_ADDR"))
	require.Nil(t, err)

	addr := os.Getenv("ADDR")

	pub, priv, err := ssh.GenKeyPair()
	require.Nil(t, err)

	spub, err := vault.SignSSHKey(vaultConfig, string(pub))
	require.Nil(t, err)

	cp := CommonPlatform{
		SshKey: CloudletSSHKey{
			PrivateKey:      string(priv),
			SignedPublicKey: string(spub),
		},
	}
	client, err := cp.GetSSHClientFromIPAddr(ctx, addr, pc.WithUser(SSHUser))
	require.Nil(t, err)
	out, err := client.Output("sudo grep 'Finished edgecloud init' /var/log/edgecloud.log")
	if err != nil {
		out, err = client.Output("sudo grep 'Finished mobiledgex init' /var/log/mobiledgex.log")
	}
	require.Nil(t, err)
	fmt.Printf("%s\n", out)
}

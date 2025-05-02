// Copyright 2025 EdgeXR, Inc
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

package nodemgr

import (
	"fmt"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/test-go/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCheckNode(t *testing.T) {
	// this tests a real node, you will need to set the env
	// vars to run this test.
	// To copy your pub key to the node, run:
	// ssh-copy-id -i ~/.ssh/id_rsa.pub user@hostname
	privKeyFile := os.Getenv("NODE_PRIV_KEY_FILE")
	nodeAddr := os.Getenv("NODE_ADDR")
	username := os.Getenv("NODE_USERNAME")
	if nodeAddr == "" || privKeyFile == "" || username == "" {
		t.Skip("Skipping test as env vars not set")
	}
	privKeyData, err := os.ReadFile(privKeyFile)
	require.Nil(t, err)
	node := &edgeproto.Node{
		MgmtAddr: nodeAddr,
		SshPort:  22,
		Username: username,
	}
	info, err := CheckNode(node, privKeyData)
	require.Nil(t, err)
	out, err := yaml.Marshal(info)
	require.Nil(t, err)
	fmt.Println(string(out))
}

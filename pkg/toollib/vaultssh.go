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

package toollib

import (
	"fmt"
	"os"

	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	ssh "github.com/edgexr/golang-ssh"
)

func GetSSHAuth(domain, vaultAddr, vaultToken string) (*ssh.Auth, error) {
	if vaultAddr == "" {
		vaultAddr = os.Getenv("VAULT_ADDR")
	}
	if vaultAddr == "" {
		if domain != "" {
			// assume address
			vaultAddr = "https://vault." + domain
			fmt.Printf("vault address not specified, using %s\n", vaultAddr)
		} else {
			return nil, fmt.Errorf("vault address not specified, may use env var VAULT_ADDR")
		}
	}
	if vaultToken == "" {
		vaultToken = os.Getenv("VAULT_TOKEN")
	}
	if vaultToken == "" {
		return nil, fmt.Errorf("vault token not specified, may use env var VAULT_TOKEN")
	}

	pubKeyData, privKeyData, err := ssh.GenKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair, %s", err)
	}

	vaultConfig := &vault.Config{
		Addr: vaultAddr,
		Auth: vault.NewTokenAuth(vaultToken),
	}
	signedPubKey, err := vault.SignSSHKey(vaultConfig, string(pubKeyData))
	if err != nil {
		return nil, err
	}
	auth := ssh.Auth{
		KeyPairs: []ssh.KeyPair{{
			PublicRawKey:  []byte(signedPubKey),
			PrivateRawKey: []byte(privKeyData),
		}},
	}
	return &auth, nil
}

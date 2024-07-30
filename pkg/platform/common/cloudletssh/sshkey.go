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

// Package cloudletssh provides for a shareable, on-demand provider
// of signed ssh keys.
package cloudletssh

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	xssh "golang.org/x/crypto/ssh"
)

// SSHKey provides on-demand signed ssh certificates for authenticating
// with VMs created by the platform.
type SSHKey struct {
	publicKey         string
	signedPublicKey   string
	privateKey        string
	signer            KeySigner
	mux               sync.Mutex
	expiresAt         time.Time
	refreshInProgress bool
}

// KeySigner is used to sign the user's public key
type KeySigner interface {
	// SignSSHKey signs the user's public key and returns a signed ssh certificate
	SignSSHKey(ctx context.Context, publicKey string) (string, error)
}

var SignSSHKeyTimeout = 30 * time.Second
var RefreshBufferDuration = 2 * time.Hour

func NewSSHKey(signer KeySigner) *SSHKey {
	return &SSHKey{
		signer: signer,
	}
}

func (s *SSHKey) getSignedKey(ctx context.Context) (string, time.Time, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Sign cloudlet public key from Vault")

	ctx, cancel := context.WithTimeout(ctx, SignSSHKeyTimeout)
	defer cancel()

	signedKey, err := s.signer.SignSSHKey(ctx, s.publicKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign cloudlet ssh key, %s", err)
	}
	// set expiration time
	pk, err := xssh.ParsePublicKey([]byte(signedKey))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse signed cloudlet key, %s", err)
	}
	cert := pk.(*xssh.Certificate)
	expiresAt := time.Unix(int64(cert.ValidBefore), 0)
	return signedKey, expiresAt, nil
}

func (s *SSHKey) ensureSignedKeyLocked(ctx context.Context) error {
	now := time.Now()
	if s.signedPublicKey == "" || now.After(s.expiresAt) {
		// no valid signed key, do network call inline under lock
		// because we need to wait for the call to finish anyway
		signedKey, expiresAt, err := s.getSignedKey(ctx)
		if err != nil {
			return err
		}
		s.signedPublicKey = signedKey
		s.expiresAt = expiresAt
	} else if now.After(s.expiresAt.Add(-RefreshBufferDuration)) && !s.refreshInProgress {
		// current key is still valid but expiring soon, spawn
		// thread to refresh it
		s.refreshInProgress = true
		go func() {
			span := log.StartSpan(log.DebugLevelInfra, "thread sign cloudlet ssh key")
			defer span.Finish()
			ctx := log.ContextWithSpan(context.Background(), span)

			signedKey, expiresAt, err := s.getSignedKey(ctx)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to refresh cloudlet ssh key", "err", err)
				return
			}
			s.mux.Lock()
			defer s.mux.Unlock()
			s.signedPublicKey = signedKey
			s.expiresAt = expiresAt
			s.refreshInProgress = false
		}()
	}
	return nil
}

func (s *SSHKey) genKeys(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitCloudletSSHKeys")
	cloudletPubKey, cloudletPrivKey, err := ssh.GenKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate cloudlet SSH key pair: %v", err)
	}
	s.publicKey = cloudletPubKey
	s.privateKey = cloudletPrivKey
	return nil
}

func (s *SSHKey) GetKeyPairs(ctx context.Context) ([]ssh.KeyPair, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.privateKey == "" {
		if err := s.genKeys(ctx); err != nil {
			return nil, err
		}
	}
	if err := s.ensureSignedKeyLocked(ctx); err != nil {
		return nil, err
	}
	keyPairs := []ssh.KeyPair{{
		PublicRawKey:  []byte(s.signedPublicKey),
		PrivateRawKey: []byte(s.privateKey),
	}}
	return keyPairs, nil
}

func (s *SSHKey) GetKeyPairsCb(ctx context.Context) func() ([]ssh.KeyPair, error) {
	return func() ([]ssh.KeyPair, error) {
		return s.GetKeyPairs(ctx)
	}
}

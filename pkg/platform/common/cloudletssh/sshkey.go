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
	refreshErr        error
	refreshWait       sync.WaitGroup
}

// KeySigner is used to sign the user's public key
type KeySigner interface {
	// SignSSHKey signs the user's public key and returns a signed ssh certificate
	SignSSHKey(ctx context.Context, publicKey string) (string, error)
}

var SignSSHKeyTimeout = 30 * time.Second
var RefreshInlineBufferDuration = time.Minute
var RefreshLazyBufferDuration = 2 * time.Hour

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
	// determine expiration time
	pk, err := xssh.ParsePublicKey([]byte(signedKey))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse signed cloudlet key, %s", err)
	}
	cert := pk.(*xssh.Certificate)
	expiresAt := time.Unix(int64(cert.ValidBefore), 0)
	return signedKey, expiresAt, nil
}

func (s *SSHKey) refreshSignedKey(ctx context.Context) bool {
	waitForRefresh := false
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.privateKey == "" {
		if err := s.genKeys(ctx); err != nil {
			s.refreshErr = err
			return waitForRefresh
		}
	}
	now := time.Now()
	if now.After(s.expiresAt.Add(-RefreshLazyBufferDuration)) && !s.refreshInProgress {
		// cert should or needs to be refreshed, spawn a thread to refresh it.
		s.refreshInProgress = true
		s.refreshWait.Add(1)
		go func() {
			defer s.refreshWait.Done()
			span := log.StartSpan(log.DebugLevelInfra, "thread sign cloudlet ssh key")
			defer span.Finish()
			ctx := log.ContextWithSpan(context.Background(), span)

			signedKey, expiresAt, err := s.getSignedKey(ctx)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to refresh cloudlet ssh key", "err", err)
			}
			s.mux.Lock()
			defer s.mux.Unlock()
			s.refreshInProgress = false
			s.refreshErr = err
			if err == nil {
				s.signedPublicKey = signedKey
				s.expiresAt = expiresAt
			}
		}()
	}
	if now.After(s.expiresAt.Add(-RefreshInlineBufferDuration)) {
		// refresh thread was spawned or already in progress,
		// but the time to expiration is too soon (or already expired),
		// so we must wait inline until refresh finishes.
		waitForRefresh = true
	}
	return waitForRefresh
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
	waitForRefresh := s.refreshSignedKey(ctx)
	if waitForRefresh {
		s.refreshWait.Wait()
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.refreshErr != nil {
		return nil, s.refreshErr
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

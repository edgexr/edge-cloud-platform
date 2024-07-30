// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudletssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type keySigner struct {
	signer      ssh.MultiAlgorithmSigner
	signedCount int
	validDur    time.Duration
}

func (s *keySigner) init(validDur time.Duration) error {
	caKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		return err
	}
	mas, err := ssh.NewSignerWithAlgorithms(signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA256})
	if err != nil {
		return err
	}
	s.signer = mas
	s.validDur = validDur
	return nil
}

func (s *keySigner) SignSSHKey(ctx context.Context, publicKey string) (string, error) {
	keyParts := strings.Split(publicKey, " ")
	if len(keyParts) > 1 {
		// Someone has sent the 'full' public key rather than just the base64 encoded part that the ssh library wants
		publicKey = keyParts[1]
	}
	decodedKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("key signer failed to decode user public key, %s", err)
	}
	userPubKey, err := ssh.ParsePublicKey([]byte(decodedKey))
	if err != nil {
		return "", fmt.Errorf("key signer parse user public key failed, %s", err)
	}
	now := time.Now()
	cert := ssh.Certificate{
		Key:         userPubKey,
		CertType:    ssh.UserCert,
		ValidAfter:  uint64(now.Add(-time.Second).In(time.UTC).Unix()),
		ValidBefore: uint64(now.Add(s.validDur).In(time.UTC).Unix()),
	}
	if err := cert.SignCert(rand.Reader, s.signer); err != nil {
		return "", fmt.Errorf("key signer sign cert failed, %s", err)
	}
	s.signedCount++
	out := cert.Marshal()
	return string(out), nil
}

func TestSSHKeyRefresh(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	SignSSHKeyTimeout = 2 * time.Second
	RefreshBufferDuration = time.Minute

	validDur := time.Hour
	ks := keySigner{}
	err := ks.init(validDur)
	require.Nil(t, err)

	sshKey := NewSSHKey(&ks)
	_, err = sshKey.GetKeyPairs(ctx)
	require.Nil(t, err)
	require.Equal(t, 1, ks.signedCount)
	// ensure we parsed the correct expiration time
	now := time.Now()
	require.Greater(t, sshKey.expiresAt, now.Add(validDur).Add(-time.Minute))
	require.Less(t, sshKey.expiresAt, now.Add(validDur).Add(time.Minute))
	// getting the key should not trigger a refresh
	_, err = sshKey.GetKeyPairs(ctx)
	require.Nil(t, err)
	require.Equal(t, 1, ks.signedCount)
	// test inline refresh
	curCert := sshKey.signedPublicKey
	sshKey.expiresAt = now.Add(-time.Minute)
	pair, err := sshKey.GetKeyPairs(ctx)
	require.Nil(t, err)
	require.Equal(t, 2, ks.signedCount)
	require.Equal(t, 1, len(pair))
	require.NotEqual(t, curCert, string(pair[0].PublicRawKey)) // should get new cert
	// test go thread refresh
	curCert = sshKey.signedPublicKey
	sshKey.expiresAt = time.Now().Add(RefreshBufferDuration / 2)
	pair, err = sshKey.GetKeyPairs(ctx)
	require.Nil(t, err)
	require.Equal(t, 1, len(pair))
	require.Equal(t, curCert, string(pair[0].PublicRawKey)) // should get cur cert
	updated := false
	for ii := 0; ii < 20; ii++ {
		// thread finishes when it updates the cert
		sshKey.mux.Lock()
		if curCert != sshKey.signedPublicKey {
			updated = true
		}
		sshKey.mux.Unlock()
		if updated {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, updated)
	require.Equal(t, 3, ks.signedCount)
}

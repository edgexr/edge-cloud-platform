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

package cloudcommon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

func getE2ECertsDir() string {
	return os.Getenv("HOME") + "/e2e-certs"
}

const e2eCAName = "e2e-ca"

func GetCloudletE2EPublicCert(ctx context.Context, commonName string) (*vault.PublicCert, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get cloudlet e2e public cert", "commonName", commonName)
	// make sure certs dir is present
	certsDir := getE2ECertsDir()
	err := os.MkdirAll(certsDir, 0755)
	if err != nil {
		return nil, err
	}

	// return cert if it already exists
	pubCert, err := readCloudletE2EPublicCert(ctx, commonName)
	if err == nil {
		return pubCert, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// cert does not exist, create it now

	// make sure CA cert is present
	if _, err := os.Stat(certsDir + "/out/" + e2eCAName + ".crt"); errors.Is(err, os.ErrNotExist) {
		// initialize CA cert
		cmd := exec.Command("certstrap", "init", "--common-name", e2eCAName, "--passphrase", "")
		cmd.Dir = certsDir
		log.SpanLog(ctx, log.DebugLevelInfra, "generating self-signed cloudlet CA", "dir", certsDir, "cmd", cmd.String())
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("command failed, %s, %s, %s", cmd.String(), string(out), err)
		}
	}

	// generate key and csr
	cmd := exec.Command("certstrap", "request-cert", "--domain", commonName+",localhost", "--ip", "127.0.0.1", "--passphrase", "")
	cmd.Dir = certsDir
	log.SpanLog(ctx, log.DebugLevelInfra, "generating server key and csr", "dir", certsDir, "name", commonName, "cmd", cmd.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("command failed, %s, %s, %s", cmd.String(), string(out), err)
	}

	// extract public key
	cmd = exec.Command("openssl", "rsa", "-in", "out/"+commonName+".key", "-pubout", "-out", "out/"+commonName+".pub")
	cmd.Dir = certsDir
	log.SpanLog(ctx, log.DebugLevelInfra, "extracting server public key", "dir", certsDir, "name", commonName, "cmd", cmd.String())
	out, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("command failed, %s, %s, %s", cmd.String(), string(out), err)
	}

	// sign certificate
	cmd = exec.Command("certstrap", "sign", "--CA", e2eCAName, commonName)
	cmd.Dir = certsDir
	log.SpanLog(ctx, log.DebugLevelInfra, "signing server public key", "dir", certsDir, "name", commonName, "cmd", cmd.String())
	out, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("command failed, %s, %s, %s", cmd.String(), string(out), err)
	}

	return readCloudletE2EPublicCert(ctx, commonName)
}

func readCloudletE2EPublicCert(ctx context.Context, commonName string) (*vault.PublicCert, error) {
	certsDir := getE2ECertsDir()
	pubCert := &vault.PublicCert{}
	// read signed certificate
	out, err := os.ReadFile(certsDir + "/out/" + commonName + ".crt")
	if err != nil {
		return nil, err
	}
	pubCert.Cert = string(out)

	// read private key
	out, err = os.ReadFile(certsDir + "/out/" + commonName + ".key")
	if err != nil {
		return nil, err
	}
	pubCert.Key = string(out)
	return pubCert, nil
}

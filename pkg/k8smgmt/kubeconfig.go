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

package k8smgmt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	"k8s.io/client-go/tools/clientcmd"
)

const KconfPerms fs.FileMode = 0644

// EnsureKubeconfig ensures the kubeconfig is preset
func EnsureKubeconfig(ctx context.Context, client ssh.Client, filename string, kconfData []byte) error {
	data, err := pc.ReadFile(ctx, client, filename, pc.NoSudo)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to read kubeconfig %s, will try to write it anyway, %s", err)
	}
	if bytes.Equal(kconfData, []byte(data)) {
		return nil
	}
	err = pc.WriteFile(client, filename, string(kconfData), "kubeconfig", pc.NoSudo)
	if err != nil {
		return fmt.Errorf("failed to write kubeconfig %s, %s", filename, err)
	}
	return nil
}

// EnsureKubeconfigs ensures the necessary kubeconfigs are present
func EnsureKubeconfigs(ctx context.Context, client ssh.Client, names *KubeNames, kconfData []byte) error {
	// ensure the full access kubeconfig is present
	err := EnsureKubeconfig(ctx, client, names.KconfName, kconfData)
	if err != nil {
		return err
	}
	// ensure the namespace-scoped kubeconfig is present if needed
	if names.InstanceNamespace != "" {
		// kconfData must be scoped to namespace
		// TODO: this just defaults to the namespace, but does not
		// enforce. In the future the kubeconfig should not allow
		// read/writes outside of the tenant namespace/vcluster.
		config, err := clientcmd.Load(kconfData)
		if err != nil {
			return fmt.Errorf("failed to load kubeconfig data, %s", err)
		}
		context, ok := config.Contexts[config.CurrentContext]
		if ok {
			context.Namespace = names.InstanceNamespace
		}
		out, err := clientcmd.Write(*config)
		if err != nil {
			return fmt.Errorf("failed to marshal multi-tenant kubeconfig, %s", err)
		}
		err = EnsureKubeconfig(ctx, client, names.TenantKconfName, out)
		if err != nil {
			return err
		}
	}
	return nil
}

func RemoveKubeconfigs(ctx context.Context, client ssh.Client, names *KubeNames) error {
	err := pc.DeleteFile(client, names.KconfName, pc.NoSudo)
	if err != nil {
		return err
	}
	return RemoveTenantKubeconfig(ctx, client, names)
}

func RemoveTenantKubeconfig(ctx context.Context, client ssh.Client, names *KubeNames) error {
	if names.TenantKconfName != "" {
		err := pc.DeleteFile(client, names.TenantKconfName, pc.NoSudo)
		if err != nil {
			return err
		}
	}
	return nil
}

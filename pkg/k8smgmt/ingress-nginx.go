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
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	ssh "github.com/edgexr/golang-ssh"
)

const (
	IngressNginxChart             = "ingress-nginx"
	IngressNginxName              = "ingress-nginx"
	IngressNginxNamespace         = "ingress-nginx"
	IngressNginxRepoURL           = "https://kubernetes.github.io/ingress-nginx"
	IngressNginxChartVersion      = "4.11.3" // app version 1.11.3
	IngressNginxExternalIPRetry   = 2 * time.Second
	IngressNginxExternalIPRetries = 30
	IngressDefaultCertSecret      = "default-cert"
)

type RefreshCertsOpts struct {
	CommerialCerts bool
	InitCluster    bool // force create of secret to ensure it exists
}

// RefreshCert refreshes the specified wildcard cert for the
// cloudlet in the cluster pointed to by the KConfNames.
// The certificate is used as the default certificate for
// all ingress instances in the cluster.
func RefreshCert(ctx context.Context, client ssh.Client, names *KconfNames, cloudletKey *edgeproto.CloudletKey, cache *certscache.ProxyCertsCache, namespace, wildcardName string, opts RefreshCertsOpts) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "k8s refresh ingress certs", "cloudlet", cloudletKey, "certName", wildcardName, "secret", IngressDefaultCertSecret, "opts", opts)
	if os.Getenv("E2ETEST_TLS") != "" {
		opts.CommerialCerts = false
	}

	cert, updated, err := cache.RefreshCert(ctx, cloudletKey, wildcardName, opts.CommerialCerts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "k8s failed to refresh ingress certs", "certName", wildcardName, "err", err)
		return err
	}

	if !updated && !opts.InitCluster {
		// make sure secret exists
		cmd := fmt.Sprintf("kubectl %s get secret -n %s %s", names.KconfArg, namespace, IngressDefaultCertSecret)
		_, err := client.Output(cmd)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "cert not updated and secret exists, no need to refresh", "secret", IngressDefaultCertSecret, "namespace", namespace)
			return nil
		}
	}
	fileName := strings.Replace(wildcardName, "*", "_", 1)

	err = pc.WriteFile(client, fileName+".crt", cert.CertString, "cert", pc.NoSudo)
	if err != nil {
		return fmt.Errorf("failed to write cert file %s.crt, %s", fileName, err)
	}
	err = pc.WriteFile(client, fileName+".key", cert.KeyString, "cert", pc.NoSudo)
	if err != nil {
		return fmt.Errorf("failed to write cert key file %s.key, %s", fileName, err)
	}
	// this command generates a yaml file then applies it, to allow
	// us to update the secret if it already exists
	cmd := fmt.Sprintf("kubectl %s create secret -n %s tls %s --key %s.key --cert %s.crt --save-config --dry-run=client -o yaml | kubectl %s apply -f -", names.KconfArg, namespace, IngressDefaultCertSecret, fileName, fileName, names.KconfArg)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to write cert secret: %s, %s", out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "refreshed cert", "cmd", cmd)
	return nil
}

// InstallIngressNginx installs the ingress-nginx controller
// in the cluster.
func InstallIngressNginx(ctx context.Context, client ssh.Client, names *KconfNames, ops ...IngressNginxOp) error {
	opts := &IngressNginxOptions{}
	for _, op := range ops {
		op(opts)
	}
	// This specifies a default certificate, which should be a
	// wildcard cert for the entire cluster/cloudlet.
	cmd := fmt.Sprintf("helm %s upgrade --install %s %s --repo %s --namespace %s --create-namespace --version %s --set controller.extraArgs.default-ssl-certificate=%s/%s %s", names.KconfArg, IngressNginxName, IngressNginxChart, IngressNginxRepoURL, IngressNginxNamespace, IngressNginxChartVersion, IngressNginxNamespace, IngressDefaultCertSecret, strings.Join(opts.helmSetCmds, " "))
	log.SpanLog(ctx, log.DebugLevelInfra, "install ingress nginx", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "helm install ingress-nginx failed", "out", string(out), "err", err)
		return fmt.Errorf("ingress-nginx install failed: %s, %s", string(out), err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "wait for ingress nginx deployment ready")
	err = WaitForDeploymentReady(ctx, client, names, "ingress-nginx-controller", IngressNginxNamespace, 40, 3*time.Second)
	if err != nil {
		return err
	}

	if opts.waitForExternalIP {
		externalIP := ""
		log.SpanLog(ctx, log.DebugLevelInfra, "install ingress nginx waiting for external IP")
		for ii := 0; ii < IngressNginxExternalIPRetries; ii++ {
			svcs, err := GetKubeServices(ctx, client, names, WithObjectNamespace(IngressNginxNamespace))
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "ingress nginx check svc failed", "err", err)
				return err
			}
			if len(svcs) > 0 {
				if len(svcs[0].Status.LoadBalancer.Ingress) > 0 {
					externalIP = svcs[0].Status.LoadBalancer.Ingress[0].IP
				}
				if externalIP != "" {
					break
				}
			}
			time.Sleep(IngressNginxExternalIPRetry)
		}
		if externalIP == "" {
			return errors.New("timed out waiting for ingress nginx external IP to be assigned")
		}
	}
	return nil
}

// SetupIngressNginx is a convenience function that creates the
// namespace, creates the default certificate, and installs the
// ingress-nginx controller.
func SetupIngressNginx(ctx context.Context, client ssh.Client, names *KconfNames, cloudletKey *edgeproto.CloudletKey, certsCache *certscache.ProxyCertsCache, wildcardName string, refreshOpts RefreshCertsOpts, namespaceLabels map[string]string, updateCallback edgeproto.CacheUpdateCallback, ops ...IngressNginxOp) error {
	// set up namespace so we can write the default cert
	err := EnsureNamespace(ctx, client, names, IngressNginxNamespace, namespaceLabels)
	if err != nil {
		return err
	}

	// install default cert for ingress
	updateCallback(edgeproto.UpdateTask, "Generating ingress certificate")
	err = RefreshCert(ctx, client, names, cloudletKey, certsCache, IngressNginxNamespace, wildcardName, refreshOpts)
	if err != nil {
		return err
	}

	// install ingress-nginx
	updateCallback(edgeproto.UpdateTask, "Installing ingress controller")
	err = InstallIngressNginx(ctx, client, names, ops...)
	if err != nil {
		return err
	}
	return nil
}

type IngressNginxOptions struct {
	waitForExternalIP bool
	helmSetCmds       []string
}

type IngressNginxOp func(*IngressNginxOptions)

func WithIngressNginxWaitForExternalIP() IngressNginxOp {
	return func(opts *IngressNginxOptions) {
		opts.waitForExternalIP = true
	}
}

func WithIngressNginxHelmSetCmd(cmd string) IngressNginxOp {
	return func(opts *IngressNginxOptions) {
		opts.helmSetCmds = append(opts.helmSetCmds, cmd)
	}
}

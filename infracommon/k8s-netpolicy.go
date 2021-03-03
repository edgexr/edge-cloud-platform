package infracommon

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"

	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type K8sNetworkPolicyParams struct {
	PolicyName string
	Namespace  string
}

var k8sNetworkPolicyTemplate = `kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: {{.PolicyName}}
  namespace: {{.Namespace}}
spec:
  podSelector:
    matchLabels:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: {{.Namespace}}
    - ipBlock:
        cidr: 0.0.0.0/0
`

// CreateK8sNetworkPolicyManifest returns the manifest filename
func CreateK8sNetworkPolicyManifest(ctx context.Context, client ssh.Client, policyName, namespace, dir string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateK8sNetworkPolicyFile", "policyName", policyName, "namespace", namespace, "dir", dir)

	err := pc.CreateDir(ctx, client, dir, pc.NoOverwrite)
	if err != nil {
		return "", fmt.Errorf("unable to create directory: %s for network policy: %v", dir, err)
	}
	fileName := dir + "/" + policyName + ".yml"
	policyParams := K8sNetworkPolicyParams{
		PolicyName: policyName,
		Namespace:  namespace,
	}
	pBuf, err := ExecTemplate("k8sPolicyManifest", k8sNetworkPolicyTemplate, policyParams)
	if err != nil {
		return "", fmt.Errorf("Error in policy exec template: %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Creating Policy file", "fileName", fileName, "policyParams", policyParams)
	err = pc.WriteFile(client, fileName, pBuf.String(), "k8s-manifest", pc.NoSudo)
	if err != nil {
		return "", fmt.Errorf("unable to write policy manifest file %s: %s", fileName, err.Error())
	}
	return fileName, nil
}

func ApplyK8sNetworkPolicyManifest(ctx context.Context, client ssh.Client, fileName, kubeConfigFile string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ApplyK8sNetworkPolicyManifest", "fileName", fileName)
	cmd := fmt.Sprintf("kubectl apply -f %s --kubeconfig=%s", fileName, kubeConfigFile)
	out, err := client.Output(cmd)
	log.SpanLog(ctx, log.DebugLevelInfra, "run policy file apply", "cmd", cmd, "out", out, "err", err)
	if err != nil {
		return fmt.Errorf("Error in apply network policy: %s - %v", out, err)
	}
	return nil
}

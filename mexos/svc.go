package mexos

type ksaPort struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
	NodePort   int    `json:"nodePort"`
	TargetPort int    `json:"targetPort"`
}

type ksaSpec struct {
	Ports []ksaPort `json:"ports"`
}

type kubernetesServiceAbbrev struct {
	Spec ksaSpec `json:"spec"`
}

type ingressItem struct {
	IP string `json:"ip"`
}

type loadBalancerItem struct {
	Ingresses []ingressItem `json:"ingress"`
}

type statusItem struct {
	LoadBalancer loadBalancerItem `json:"loadBalancer"`
}

type metadataItem struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace"`
	CreationTimestamp string `json:"creationTimestamp"`
	ResourceVersion   string `json:"resourceVersion"`
	UID               string `json:"uid"`
}

type svcItem struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Metadata   metadataItem `json:"metadata"`
	Spec       interface{}  `json:"spec"`
	Status     statusItem   `json:"status"`
}

type svcItems struct {
	Items []svcItem `json:"items"`
}

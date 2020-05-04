package infracommon

import "k8s.io/api/core/v1"

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

type svcItems struct {
	Items []v1.Service `json:"items"`
}

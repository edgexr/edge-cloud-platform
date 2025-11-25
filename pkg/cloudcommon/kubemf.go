// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudcommon

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
	yaml "github.com/mobiledgex/yaml/v2"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes/scheme"
)

const yamlSeparator = "\n---"

func DecodeK8SYaml(manifest string) ([]runtime.Object, []*schema.GroupVersionKind, error) {
	files := strings.Split(manifest, yamlSeparator)
	decode := scheme.Codecs.UniversalDeserializer().Decode
	objs := []runtime.Object{}
	kinds := []*schema.GroupVersionKind{}

	for _, file := range files {
		file = strings.TrimSpace(file)
		if len(file) == 0 {
			continue
		}
		obj, kind, err := decode([]byte(file), nil, nil)
		if err != nil {
			return nil, nil, err
		}
		objs = append(objs, obj)
		kinds = append(kinds, kind)
	}
	return objs, kinds, nil
}

type DockerContainer struct {
	Image string `mapstructure:"image"`
}

func DecodeDockerComposeYaml(manifest string) (map[string]DockerContainer, error) {
	obj := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(manifest), &obj)
	if err != nil {
		return nil, err
	}
	if _, ok := obj["services"]; !ok {
		return nil, fmt.Errorf("unable to find services in docker compose file")
	}
	containers := make(map[string]DockerContainer)
	err = mapstructure.Decode(obj["services"], &containers)
	if err != nil {
		return nil, err
	}
	return containers, nil
}

func EncodeK8SYaml(objs []runtime.Object) (string, error) {
	var files []string
	printer := &printers.YAMLPrinter{}
	for _, o := range objs {
		if o == nil {
			continue
		}
		buf := bytes.Buffer{}
		err := printer.PrintObj(o, &buf)
		if err != nil {
			return "", fmt.Errorf("unable to marshal the k8s objects back together, %s", err.Error())
		} else {
			file := buf.String()
			if _, ok := o.(*networkingv1.NetworkPolicy); ok {
				// NetworkPolicyStatus has been removed as of
				// https://github.com/kubernetes/api/commit/90ceadb2d5f2f1d135492b647c9fb72777db4b36
				// unfortunately yaml printer writes it as an empty {}
				// field, we need to remove it
				file = strings.TrimSuffix(file, "status: {}\n")
			}
			files = append(files, file)
		}
	}
	mf := strings.Join(files, "---\n")
	return mf, nil
}

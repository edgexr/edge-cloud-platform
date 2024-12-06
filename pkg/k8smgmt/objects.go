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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
)

var ErrObjectNotFound = errors.New("not found")

// GetObjects gets kubernetes objects of the specified type
// using "kubectl get ...". The output data will be an object
// with an "items" field which is a list of the expected type.
func GetObjects(ctx context.Context, client ssh.Client, names *KconfNames, objType string, outData any, ops ...GetObjectsOp) error {
	return GetObject(ctx, client, names, objType, "", outData, ops...)
}

// GetObject gets a kubernetes object of the specified type
// using "kubectl get ...". The output data is an object of that
// type. If the named object does not exist, this will return a
// not found error that can be checked using:
// errors.Is(err, ErrObjectNotFound).
func GetObject(ctx context.Context, client ssh.Client, names *KconfNames, objType, name string, outData any, ops ...GetObjectsOp) error {
	opts := GetObjectsOptions{}
	for _, op := range ops {
		op(&opts)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "get objects", "objType", objType, "name", name, "kconf", names.KconfName, "opts", opts)

	ns := "-A"
	if opts.namespace != "" {
		ns = "-n " + opts.namespace
	}
	labels := ""
	for _, label := range opts.labels {
		labels += " -l " + label
	}

	cmd := fmt.Sprintf("kubectl %s get %s %s -o json %s %s", names.KconfArg, objType, name, ns, labels)
	out, err := client.Output(cmd)
	if err != nil {
		if name != "" && strings.Contains(out, fmt.Sprintf("%q not found", name)) {
			return fmt.Errorf("%s %q %w", objType, name, ErrObjectNotFound)
		}
		return fmt.Errorf("failed to get %s: %s, %s, %v", objType, cmd, out, err)
	}
	err = json.Unmarshal([]byte(out), outData)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot unmarshal json", "objType", objType, "name", name, "out", out, "err", err)
		return fmt.Errorf("cannot unmarshal get object json, %s", err.Error())
	}
	return nil
}

type GetObjectsOptions struct {
	namespace string
	labels    []string // name=value
}

type GetObjectsOp func(*GetObjectsOptions)

func WithObjectNamespace(ns string) GetObjectsOp {
	return func(opts *GetObjectsOptions) {
		opts.namespace = ns
	}
}

func WithObjectLabel(name, val string) GetObjectsOp {
	return func(opts *GetObjectsOptions) {
		opts.labels = append(opts.labels, name+"="+val)
	}
}

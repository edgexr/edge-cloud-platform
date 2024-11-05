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

package clustersvc

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

// This file contains inference app creation for later instantiation
// This is intended for when the platform deployed has Inference capabilities

const (
	Llama3_2_8B  = "llama3.2-8B"
	Llama3_1_40B = "llama3.1-40B"
)

var CpuInferenceManfest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: chatbot
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gradio
  template:
    metadata:
      labels:
        app: gradio
    spec:
      containers:
        - name: gradio
          image: ghcr.io/levshvarts/ragchatbot:2024-10-03
          imagePullPolicy: Always
          ports:
            - containerPort: 7860
          env:
            - name: LLM_URL
              valueFrom:
                configMapKeyRef:
                  name: stack-config
                  key: LLM_URL
            - name: EMBEDDINGS_URL
              valueFrom:
                configMapKeyRef:
                  name: stack-config
                  key: EMBEDDING_SERVER_URL
            - name: VECTORDB_URL
              valueFrom:
                configMapKeyRef:
                  name: stack-config
                  key: CHROMADB_HOST

---
apiVersion: v1
kind: Service
metadata:
  name: chatbot
spec:
  type: LoadBalancer
  selector:
    app: gradio
  ports:
    - port: 7860
      targetPort: 7860
      protocol: TCP
---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: llamacpp-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    requests:
      storage: 50Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm
  namespace: default
  labels:
    app: llamacpp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: llamacpp
  template:
    metadata:
      labels:
        app: llamacpp
    spec:
      containers:
        - name: llamacpp
          image:  ghcr.io/ggerganov/llama.cpp:server
          env:
            - name: LLAMA_ARG_MODEL_URL
              value: "https://huggingface.co/QuantFactory/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct.Q8_0.gguf"
            - name: LLAMA_ARG_PORT
              value: "80"
            - name: LLAMA_ARG_N_PREDICT
              value: "512"
            - name: LLAMA_ARG_CTX_SIZE
              value: "2048"
            - name: LLAMA_ARG_HOST
              value: "0.0.0.0"
            - name: LLAMA_LOG_VERBOSITY
              value: "10"
            - name: LLAMA_ARG_CHAT_TEMPLATE
              value: "llama2"
          volumeMounts:
            - name: llamacpp-pv
              mountPath: /data
            - name: shm
              mountPath: /dev/shm
          ports:
            - containerPort: 80
      volumes:
        - name: llamacpp-pv
          persistentVolumeClaim:
            claimName: llamacpp-pvc
        - name: shm
          emptyDir:
            medium: Memory
            sizeLimit: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: llm
  namespace: default
spec:
  selector:
    app: llamacpp
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: minio-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: storage
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: minio
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: minio
    spec:
      volumes:
        - name: storage
          persistentVolumeClaim:
            claimName: minio-pvc
      containers:
        - name: minio
          image: docker.io/minio/minio:latest
          args:
            - server
            - "--console-address"
            - ":9001"
            - /storage
          env:
            - name: MINIO_ROOT_USER
              valueFrom:
                configMapKeyRef:
                  name: stack-config
                  key: MINIO_ACCESS_KEY
            - name: MINIO_ROOT_PASSWORD
              valueFrom:
                configMapKeyRef:
                  name: stack-config
                  key: MINIO_SECRET_KEY
          ports:
            - containerPort: 9000
            - containerPort: 9001
          volumeMounts:
            - name: storage
              mountPath: "/storage"
---
apiVersion: v1
kind: Service
metadata:
  name: storage
  namespace: default
spec:
  type: LoadBalancer
  ports:
    - port: 9000
      targetPort: 9000
      protocol: TCP
  selector:
    app: minio
---
apiVersion: v1
kind: Service
metadata:
  name: storage-ui
  namespace: default
spec:
  type: LoadBalancer
  ports:
    - port: 9001
      targetPort: 9001
      protocol: TCP
  selector:
    app: minio
`

func getInferenceDeploymentManifest(name string) string {
	return CpuInferenceManfest
}

func InferenceAppData() []edgeproto.App {
	return []edgeproto.App{{
		Key: edgeproto.AppKey{
			Name:         Llama3_2_8B,
			Version:      "3.2",
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		ImagePath:          "", // we deploy with a manifest
		Deployment:         cloudcommon.DeploymentTypeKubernetes,
		AccessPorts:        "tcp:7860:tls,tcp:80:tls,tcp:9001:tls", // tcp:9000:tls - minio api, don't need to expose it externally
		Trusted:            true,
		DeploymentManifest: getInferenceDeploymentManifest(Llama3_2_8B),
		ServerlessConfig: &edgeproto.ServerlessConfig{
			Vcpus: edgeproto.Udec64{Whole: 4, Nanos: 0},
			Ram:   12288,
		},
		Tags: map[string]string{cloudcommon.TagsInferenceService: "True"},
	}, {
		Key: edgeproto.AppKey{
			Name:         Llama3_1_40B,
			Version:      "3.1",
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		ImagePath:          "", // we deploy with a manifest
		Deployment:         cloudcommon.DeploymentTypeKubernetes,
		AccessPorts:        "tcp:7860:tls,tcp:80:tls,tcp:9000:tls,tcp:9001:tls", // tcp:9000:tls - minio api, don't need to expose it externally
		Trusted:            true,
		DeploymentManifest: getInferenceDeploymentManifest(Llama3_1_40B),
		ServerlessConfig: &edgeproto.ServerlessConfig{
			Vcpus: edgeproto.Udec64{Whole: 4, Nanos: 0},
			Ram:   12288,
		},
		Tags: map[string]string{cloudcommon.TagsInferenceService: "True"},
	}}
}

type sendAllRecv struct{}

func (s *sendAllRecv) RecvAllStart() {}

func (s *sendAllRecv) RecvAllEnd(ctx context.Context) {
	// once we got everything - create apps
	for _, app := range InferenceAppData() {
		if err := createAppCommon(ctx, dialOpts, &app); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to create inference app", "app", app, "err", err)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "Finished creation of inference app", "app", app)
		}
	}
}

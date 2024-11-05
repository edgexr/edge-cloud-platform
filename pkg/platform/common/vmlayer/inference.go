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

package vmlayer

import (
	"context"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
)

var RAGStackManifest = `apiVersion: v1
kind: ConfigMap
metadata:
  name: stack-config
  namespace: default
data:
  MINIO_SERVER_URL: "storage:9000" #minio svc
  MINIO_ACCESS_KEY: "minio"
  MINIO_SECRET_KEY: "minio123"
  WEBHOOK_ENDPOINT: "http://webhook:8082" #minio webhook - chunks the files and builds saves embeddings into chroma db
  WEBHOOK_PORT: "8082"
  MINIO_ALIAS: "myminio"
  MINIO_BUCKET_NAME: "pdfs"
  CHROMADB_HOST: "vectordb" # chroma db alias name
  CHROMADB_PORT: "8000"
  EMBEDDING_SERVER_URL: "http://embeddings/embed" # text inference embeddings
  LLM_URL: "http://llm/v1/chat/completions" # inference server
  COLLECTION_NAME: "pdfs"
---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: tei-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    limits:
      storage: 100Mi
    requests:
      storage: 50Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: embeddings
  namespace: default
  labels:
    app: tei
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tei
  template:
    metadata:
      labels:
        app: tei
    spec:
      containers:
        - name: tei
          image: ghcr.io/huggingface/text-embeddings-inference:cpu-1.5 # TODO - this should be a param for GPU-based images
          command: ["text-embeddings-router", "--model-id", "BAAI/bge-large-en-v1.5"] # TODO - there are some options missing, one - "--max-clients "
          volumeMounts:
            - name: tei-pv
              mountPath: /data
          ports:
            - containerPort: 80
      volumes:
        - name: tei-pv
          persistentVolumeClaim:
            claimName: tei-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: embeddings
  namespace: default
spec:
  selector:
    app: tei
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: LoadBalancer
---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: chroma-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    requests:
      storage: 2Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vectordb
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: chroma
  template:
    metadata:
      labels:
        app: chroma
    spec:
      containers:
        - name: chroma-server-container
          image: ghcr.io/chroma-core/chroma:0.5.16
          ports:
            - containerPort: 8000
          volumeMounts:
            - name: chroma-pv
              mountPath: /chroma/chroma/
      volumes:
        - name: chroma-pv
          persistentVolumeClaim:
            claimName: chroma-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: vectordb
  namespace: default
spec:
  selector:
    app: chroma
  ports:
    - protocol: TCP
      port: 8000
      targetPort: 8000
  type: LoadBalancer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webhook
  template:
    metadata:
      labels:
        app: webhook
    spec:
      containers:
        - name: webhook
          image: janakiramm/webhook # TODO - change repo
          imagePullPolicy: Always
          ports:
            - containerPort: 8082
          envFrom:
            - configMapRef:
                name: stack-config
---
apiVersion: v1
kind: Service
metadata:
  name: webhook
  namespace: default
spec:
  type: LoadBalancer
  ports:
    - port: 8082
      targetPort: 8082
      protocol: TCP
  selector:
    app: webhook
---
`

var MinioJobManifest = `apiVersion: batch/v1
kind: Job
metadata:
  name: storage-job
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: minio-event-configuration
          image: minio/mc
          envFrom:
            - configMapRef:
                name: stack-config
          command: ["/bin/sh", "-c"]
          args:
            - |
              mc config host add $MINIO_ALIAS http://$MINIO_SERVER_URL $MINIO_ACCESS_KEY $MINIO_SECRET_KEY &&
              mc rb $MINIO_ALIAS/$MINIO_BUCKET_NAME --force --dangerous &&
              mc mb $MINIO_ALIAS/$MINIO_BUCKET_NAME &&
              mc admin config set $MINIO_ALIAS notify_webhook:service endpoint="$WEBHOOK_ENDPOINT" queue_limit=0 &&
              mc admin service restart $MINIO_ALIAS --wait --json &&
              sleep 10 &&
              mc event add $MINIO_ALIAS/$MINIO_BUCKET_NAME arn:minio:sqs::service:webhook --event put --suffix .pdf &&
              mc event add $MINIO_ALIAS/$MINIO_BUCKET_NAME arn:minio:sqs::service:webhook --event delete --suffix .pdf &&
              mc event list $MINIO_ALIAS/$MINIO_BUCKET_NAME
      restartPolicy: Never

`
var NFSAutoProvisionAppName = cloudcommon.NFSAutoProvisionAppName
var NFSAutoProvAppVers = "1.0"

var NFSAutoProvAppKey = edgeproto.AppKey{
	Name:         NFSAutoProvisionAppName,
	Version:      NFSAutoProvAppVers,
	Organization: edgeproto.OrganizationEdgeCloud,
}

var NFSAutoProvisionApp = edgeproto.App{
	Key:           NFSAutoProvAppKey,
	ImagePath:     "https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner:nfs-subdir-external-provisioner/nfs-subdir-external-provisioner",
	Deployment:    cloudcommon.DeploymentTypeHelm,
	DelOpt:        edgeproto.DeleteType_AUTO_DELETE,
	InternalPorts: true,
	Trusted:       true,
	Annotations:   "version=4.0.18",
}

var NFSAutoProvisionAppTemplate = `nfs:
  path: /share
  server: [[ .Deployment.ClusterIp ]]
storageClass:
  name: standard
  defaultClass: true
`

func (v *VMPlatform) SetupNfsProfvisionerOperator(ctx context.Context, rootLBClient ssh.Client, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, action ActionType) error {
	appInst := edgeproto.AppInst{}
	appInst.AppKey = NFSAutoProvisionApp.Key
	appInst.ClusterKey = clusterInst.Key
	appInst.Flavor = clusterInst.Flavor

	config := edgeproto.ConfigFile{
		Kind:   edgeproto.AppConfigHelmYaml,
		Config: NFSAutoProvisionAppTemplate,
	}
	NFSAutoProvisionApp.Configs = []*edgeproto.ConfigFile{&config}

	kubeNames, err := k8smgmt.GetKubeNames(clusterInst, &NFSAutoProvisionApp, &appInst)
	if err != nil {
		return fmt.Errorf("Failed to get kubenames: %v", err)
	}
	waitFor := k8smgmt.WaitRunning
	var timeoutErr error
	switch action {
	case ActionCreate:
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setting up NFS Provisioner operator for k8s cluster"))
		err = k8smgmt.CreateHelmAppInst(ctx, rootLBClient, kubeNames, clusterInst, &NFSAutoProvisionApp, &appInst)
		if err != nil {
			return err
		}
		waitFor = k8smgmt.WaitRunning
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Waiting for NFS Provisioner operator validations to finish"))
		timeoutErr = fmt.Errorf("Timed out waiting for nfs provisioner operator pods to be online")
	case ActionDelete:
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Cleaning up NFS operator for k8s cluster"))
		err = k8smgmt.DeleteHelmAppInst(ctx, rootLBClient, kubeNames, clusterInst)
		if err != nil {
			return err
		}
		err = CleanupGPUOperatorConfigs(ctx, rootLBClient)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to cleanup NFS operator configs", "err", err)
		}
		waitFor = k8smgmt.WaitDeleted
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Waiting for NFS operator resources to be cleaned up"))
		timeoutErr = fmt.Errorf("Timed out waiting for NFS provisioner operator pods to be deleted")
	default:
		return nil
	}
	start := time.Now()
	for {
		done, err := k8smgmt.CheckPodsStatus(ctx, rootLBClient, kubeNames.KconfArg, "default", "app=nfs-subdir-external-provisioner", waitFor, start)
		if err != nil {
			return err
		}
		if done {
			break
		}
		elapsed := time.Since(start)
		if elapsed >= (GPUOperatorTimeout) {
			return timeoutErr
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

func (v *VMPlatform) SetupInferenceStack(ctx context.Context, rootLBClient ssh.Client, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, action ActionType) error {
	appInst := edgeproto.AppInst{}
	appInst.AppKey = NvidiaGPUOperatorApp.Key
	appInst.ClusterKey = clusterInst.Key
	appInst.Flavor = clusterInst.Flavor

	kubeNames, err := k8smgmt.GetKubeNames(clusterInst, &NvidiaGPUOperatorApp, &appInst)
	if err != nil {
		return fmt.Errorf("Failed to get kubenames: %v", err)
	}
	waitFor := k8smgmt.WaitRunning
	var timeoutErr error
	switch action {
	case ActionCreate:
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setting up inference stack on k8s cluster"))
		err = k8smgmt.ApplyManifest(ctx, rootLBClient, kubeNames, clusterInst, "ragstack.yaml", RAGStackManifest)
		if err != nil {
			return err
		}
		// TODO - below sleep is a hack - need to just wait for storage pod to be up and running
		time.Sleep(60 * time.Second)
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setting up inference stack on k8s cluster"))
		err = k8smgmt.ApplyManifest(ctx, rootLBClient, kubeNames, clusterInst, "minio-job.yaml", MinioJobManifest)
		if err != nil {
			return err
		}
		waitFor = k8smgmt.WaitRunning
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Waiting for Inference stack validations to finish"))
		timeoutErr = fmt.Errorf("Timed out waiting for inference operator pods to be online")
	case ActionDelete:
		fallthrough
	default:
		return nil
	}
	start := time.Now()
	for {
		done, err := k8smgmt.CheckPodsStatus(ctx, rootLBClient, kubeNames.KconfArg, "default", "app=webhook", waitFor, start)
		if err != nil {
			return err
		}
		if done {
			break
		}
		elapsed := time.Since(start)
		if elapsed >= (GPUOperatorTimeout) {
			return timeoutErr
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

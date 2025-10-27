// Copyright 2025 EdgeXR, Inc
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

package metal3

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/stretchr/testify/require"
)

// TestGetBareMetalHosts is primarily for manual testing
func TestGetBareMetalHosts(t *testing.T) {
	kubeconfig := os.Getenv("METAL3_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("METAL3_KUBECONFIG not set, skipping")
	}
	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	client := &pc.LocalClient{}

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	names := k8smgmt.KconfNames{
		KconfName: kubeconfig,
		KconfArg:  "--kubeconfig=" + kubeconfig,
	}

	hosts, err := GetBareMetalHosts(ctx, client, &names, namespace)
	require.Nil(t, err)

	for _, host := range hosts {
		consumer := ""
		consumerKind := ""
		consumerAPIVersion := ""
		if host.Spec.ConsumerRef != nil {
			consumer = host.Spec.ConsumerRef.Name
			consumerKind = host.Spec.ConsumerRef.Kind
			consumerAPIVersion = host.Spec.ConsumerRef.APIVersion
		}
		fmt.Printf("name %s, ns %s, operational-status %s, provision-state %s, consumer %s(%s/%s), bmc %s, online %t, error %s, description %s\n", host.Name, host.Namespace, host.Status.OperationalStatus, host.Status.Provisioning.State, consumer, consumerKind, consumerAPIVersion, host.Spec.BMC.Address, host.Spec.Online, host.Status.ErrorType, host.Spec.Description)
	}
}

// for reference: example BareMetalHost yaml
var _ = `
- apiVersion: metal3.io/v1alpha1
  kind: BareMetalHost
  metadata:
    annotations:
      kubectl.kubernetes.io/last-applied-configuration: |
        {"apiVersion":"metal3.io/v1alpha1","kind":"BareMetalHost","metadata":{"annotations":{},"name":"node1","namespace":"dc1"},"spec":{"bmc":{"address":"redfish-virtualmedia+https://192.168.5.143:8000/redfish/v1/Systems/50fc6f05-8438-438d-833e-61d8f7606979","credentialsName":"node1-bmc-secret","disableCertificateVerification":true},"bootMACAddress":"00:60:2f:31:81:01","bootMode":"legacy","hardwareProfile":"libvirt","online":true}}
    creationTimestamp: "2025-10-09T22:23:02Z"
    finalizers:
    - baremetalhost.metal3.io
    generation: 40
    labels:
      cluster.x-k8s.io/cluster-name: my-cluster
    name: node1
    namespace: dc1
    ownerReferences:
    - apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
      controller: true
      kind: Metal3Machine
      name: my-cluster-zlttr-ntjc8
      uid: eddefca4-8324-4018-bef2-5558a6f24acb
    resourceVersion: "336482"
    uid: 985c51cb-d8a1-4e59-8f73-5ce03da328f9
  spec:
    architecture: x86_64
    automatedCleaningMode: metadata
    bmc:
      address: redfish-virtualmedia+https://192.168.5.143:8000/redfish/v1/Systems/50fc6f05-8438-438d-833e-61d8f7606979
      credentialsName: node1-bmc-secret
      disableCertificateVerification: true
    bootMACAddress: 00:60:2f:31:81:01
    bootMode: legacy
    consumerRef:
      apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
      kind: Metal3Machine
      name: my-cluster-zlttr-ntjc8
      namespace: dc1
    hardwareProfile: libvirt
    image:
      checksum: 8bf730abc51e08ec87eb530c2595d25ff2ba2b51e08e60f6688c50b8bcf099d9
      checksumType: sha256
      format: qcow2
      url: http://192.168.5.143/UBUNTU_24.04_NODE_IMAGE_K8S_v1.34.1.qcow2
    online: true
    userData:
      name: my-cluster-zlttr-ntjc8
      namespace: dc1
  status:
    errorCount: 0
    errorMessage: ""
    goodCredentials:
      credentials:
        name: node1-bmc-secret
        namespace: dc1
      credentialsVersion: "215826"
    hardware:
      cpu:
        arch: x86_64
        count: 2
        flags:
        - apic
        - arat
        - arch_capabilities
        - arch_perfmon
        - clflush
        - cmov
        - constant_tsc
        - cpuid
        - cpuid_fault
        - cx16
        - cx8
        - de
        - ept
        - flexpriority
        - flush_l1d
        - fpu
        - fxsr
        - hypervisor
        - ibpb
        - ibrs
        - lahf_lm
        - lm
        - mca
        - mce
        - mmx
        - msr
        - mtrr
        - nopl
        - nx
        - pae
        - pat
        - pdcm
        - pge
        - pni
        - popcnt
        - pse
        - pse36
        - pti
        - rdtscp
        - rep_good
        - sep
        - ssbd
        - sse
        - sse2
        - sse4_1
        - sse4_2
        - ssse3
        - stibp
        - syscall
        - tpr_shadow
        - tsc
        - tsc_adjust
        - tsc_deadline_timer
        - tsc_known_freq
        - umip
        - vme
        - vmx
        - vnmi
        - vpid
        - x2apic
        - xtopology
        model: Intel(R) Core(TM) i7 CPU         930  @ 2.80GHz
      firmware:
        bios:
          date: 04/01/2014
          vendor: SeaBIOS
          version: 1.16.3-debian-1.16.3-2
      hostname: node1
      nics:
      - ip: 192.168.222.101
        mac: 00:60:2f:31:81:01
        model: 0x1af4 0x0001
        name: enp1s0
      - ip: fe80::8619:d984:1c4b:4115%enp1s0
        mac: 00:60:2f:31:81:01
        model: 0x1af4 0x0001
        name: enp1s0
      ramMebibytes: 4096
      storage:
      - alternateNames:
        - /dev/vda
        - /dev/disk/by-path/virtio-pci-0000:04:00.0
        name: /dev/disk/by-path/virtio-pci-0000:04:00.0
        rotational: true
        sizeBytes: 26843545600
        type: HDD
        vendor: "0x1af4"
      systemVendor:
        manufacturer: QEMU
        productName: Standard PC (Q35 + ICH9, 2009)
    hardwareProfile: libvirt
    lastUpdated: "2025-10-21T20:06:42Z"
    operationHistory:
      deprovision:
        end: "2025-10-13T22:54:40Z"
        start: "2025-10-13T22:53:38Z"
      inspect:
        end: "2025-10-09T22:25:40Z"
        start: "2025-10-09T22:23:13Z"
      provision:
        end: "2025-10-13T23:11:24Z"
        start: "2025-10-13T23:08:52Z"
      register:
        end: "2025-10-13T23:08:51Z"
        start: "2025-10-13T23:08:51Z"
    operationalStatus: OK
    poweredOn: true
    provisioning:
      ID: 48655956-4934-4564-8196-956a9f1f6aa8
      bootMode: legacy
      image:
        checksum: 8bf730abc51e08ec87eb530c2595d25ff2ba2b51e08e60f6688c50b8bcf099d9
        checksumType: sha256
        format: qcow2
        url: http://192.168.5.143/UBUNTU_24.04_NODE_IMAGE_K8S_v1.34.1.qcow2
      rootDeviceHints:
        deviceName: /dev/vda
      state: provisioned
    triedCredentials:
      credentials:
        name: node1-bmc-secret
        namespace: dc1
      credentialsVersion: "215826"
`

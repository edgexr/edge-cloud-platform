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

package controller

import (
	"fmt"
	"strings"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

const (
	NBIAppAnnotationComponentName = "NBIAppComponentName"
	NBIAppAnnotationOSArch        = "NBIAppOSArch"
	NBIAppAnnotationOSFamily      = "NBIAppOSFamily"
	NBIAppAnnotationOSLicense     = "NBIAppOSLicense"
	NBIAppAnnotationOSVersion     = "NBIAppOSVersion"
	NBIAppAnnotationRepoType      = "NBIAppRepoType"
	NBIAppRepoTypePublic          = "NBIAppRepoTypePublic"
	NBIAppRepoTypePrivate         = "NBIAppRepoTypePrivate"
)

func ProtoApp(in *nbi.AppManifest) (*edgeproto.App, error) {
	app := edgeproto.App{}
	app.Key.Name = in.Name
	app.Key.Organization = in.AppProvider
	app.Key.Version = in.Version
	if in.AppId != nil {
		app.ObjId = *in.AppId
	}
	app.AppAnnotations = map[string]string{}

	switch in.PackageType {
	case nbi.CONTAINER:
		// use kubernetes, no way to do Docker deployments
		app.Deployment = cloudcommon.DeploymentTypeKubernetes
		app.ImageType = edgeproto.ImageType_IMAGE_TYPE_DOCKER
	case nbi.HELM:
		app.Deployment = cloudcommon.DeploymentTypeHelm
		app.ImageType = edgeproto.ImageType_IMAGE_TYPE_HELM
	case nbi.OVA:
		app.Deployment = cloudcommon.DeploymentTypeVM
		app.ImageType = edgeproto.ImageType_IMAGE_TYPE_OVA
	case nbi.QCOW2:
		app.Deployment = cloudcommon.DeploymentTypeVM
		app.ImageType = edgeproto.ImageType_IMAGE_TYPE_QCOW
	}
	app.ImagePath = in.AppRepo.ImagePath
	if in.AppRepo.Type == nbi.PRIVATEREPO {
		// TODO: copy image into our repository if it's not already,
		// or tell the user to do so.
		// For now assume it's our registry, and when we go to create the
		// app, it will fail to validate the image if it's not in our
		// registry or it's not publicly reachable.
		app.AppAnnotations[NBIAppAnnotationRepoType] = NBIAppRepoTypePrivate
	} else if in.AppRepo.Type == nbi.PUBLICREPO {
		app.AppAnnotations[NBIAppAnnotationRepoType] = NBIAppRepoTypePublic
	}
	if in.AppRepo.Checksum != nil {
		// TODO: verify in.AppRepo.Checksum
	}
	if len(in.ComponentSpec) == 0 {
		return nil, fmt.Errorf("no component spec specified")
	}
	if len(in.ComponentSpec) != 1 {
		return nil, fmt.Errorf("one and only one component spec must be specified")
	}
	ports := []string{}
	for _, intf := range in.ComponentSpec[0].NetworkInterfaces {
		// proto "ANY" is not supported
		proto := ""
		switch intf.Protocol {
		case nbi.ANY:
			return nil, fmt.Errorf("component spec %s network interface %s proto ANY is not supported", in.ComponentSpec[0].ComponentName, intf.InterfaceId)
		case nbi.TCP:
			proto = "tcp"
		case nbi.UDP:
			proto = "udp"
		default:
			return nil, fmt.Errorf("component spec %s network interface %s invalid protocol %s", in.ComponentSpec[0].ComponentName, intf.InterfaceId, intf.Protocol)
		}
		tags := []string{}
		if intf.Protocol == nbi.TCP {
			// assume TLS
			tags = append(tags, "tls")
		}
		switch intf.VisibilityType {
		case nbi.VISIBILITYEXTERNAL:
		case nbi.VISIBILITYINTERNAL:
			tags = append(tags, "intvis")
		default:
			return nil, fmt.Errorf("component spec %s network interface %s unknown visiblitytype %s", in.ComponentSpec[0].ComponentName, intf.InterfaceId, intf.VisibilityType)
		}
		if intf.InterfaceId != "" {
			tags = append(tags, "id="+intf.InterfaceId)
		}
		tagStr := strings.Join(tags, ":")
		if tagStr != "" {
			tagStr = ":" + tagStr
		}
		ports = append(ports, fmt.Sprintf("%s:%d%s", proto, intf.Port, tagStr))
	}
	app.AccessPorts = strings.Join(ports, ",")

	app.AppAnnotations[NBIAppAnnotationComponentName] = in.ComponentSpec[0].ComponentName
	if in.OperatingSystem != nil {
		app.AppAnnotations[NBIAppAnnotationOSArch] = string(in.OperatingSystem.Architecture)
		app.AppAnnotations[NBIAppAnnotationOSFamily] = string(in.OperatingSystem.Family)
		app.AppAnnotations[NBIAppAnnotationOSLicense] = string(in.OperatingSystem.License)
		app.AppAnnotations[NBIAppAnnotationOSVersion] = string(in.OperatingSystem.Version)
	}
	rrVal, err := in.RequiredResources.ValueByDiscriminator()
	if err != nil {
		return nil, fmt.Errorf("failed to parse NBI App required resources, %s", err)
	}
	switch rr := rrVal.(type) {
	case nbi.KubernetesResources:
		// IsStandalone true means dedicated cluster for app
		app.AllowServerless = !rr.IsStandalone
		kr, err := protoKubernetesResources(&rr)
		if err != nil {
			return nil, err
		}
		app.KubernetesResources = kr
	case nbi.VmResources:
		return nil, fmt.Errorf("vm resources not handled yet")
	case nbi.ContainerResources:
		return nil, fmt.Errorf("container resources not handled yet")
	case nbi.DockerComposeResources:
		return nil, fmt.Errorf("docker compose resources not handled yet")
	default:
		return nil, fmt.Errorf("unhandled NBI App required resources type %T", rr)
	}
	return &app, nil
}

func protoKubernetesResources(rr *nbi.KubernetesResources) (*edgeproto.KubernetesResources, error) {
	kr := &edgeproto.KubernetesResources{}
	if rr.AdditionalStorage != nil {
		return nil, fmt.Errorf("kubernetes resources additional storage not supported")
	}
	if rr.Addons != nil {
		return nil, fmt.Errorf("kubernetes resources addons not supported yet")
	}
	if rr.Networking != nil {
		return nil, fmt.Errorf("kubernetes networking not supported yet")
	}
	if rr.Version != nil {
		kr.MinKubernetesVersion = *rr.Version
	}

	if rr.ApplicationResources.CpuPool != nil {
		cpupool := rr.ApplicationResources.CpuPool
		pool := &edgeproto.NodePoolResources{}
		pool.TotalVcpus = *edgeproto.NewUdec64(uint64(cpupool.NumCPU), 0)
		pool.TotalMemory = uint64(cpupool.Memory)
		pool.Topology = edgeproto.NodePoolTopology{}
		pool.Topology.MinNodeVcpus = uint64(cpupool.Topology.MinNodeCpu)
		pool.Topology.MinNodeMemory = uint64(cpupool.Topology.MinNodeMemory)
		pool.Topology.MinNumberOfNodes = int32(cpupool.Topology.MinNumberOfNodes)
		kr.CpuPool = pool
	}
	if rr.ApplicationResources.GpuPool != nil {
		gpupool := rr.ApplicationResources.GpuPool
		pool := &edgeproto.NodePoolResources{}
		pool.TotalVcpus = *edgeproto.NewUdec64(uint64(gpupool.NumCPU), 0)
		pool.TotalMemory = uint64(gpupool.Memory)
		pool.Topology = edgeproto.NodePoolTopology{}
		pool.Topology.MinNodeVcpus = uint64(gpupool.Topology.MinNodeCpu)
		pool.Topology.MinNodeMemory = uint64(gpupool.Topology.MinNodeMemory)
		pool.Topology.MinNumberOfNodes = int32(gpupool.Topology.MinNumberOfNodes)
		kr.GpuPool = pool
	}
	return kr, nil
}

func NBIApp(in *edgeproto.App) (*nbi.AppManifest, error) {
	am := nbi.AppManifest{}
	am.Name = in.Key.Name
	am.AppProvider = in.Key.Organization
	am.Version = in.Key.Version
	if in.ObjId != "" {
		am.AppId = &in.ObjId
	}
	switch in.Deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		am.PackageType = nbi.CONTAINER
	case cloudcommon.DeploymentTypeHelm:
		am.PackageType = nbi.HELM
	case cloudcommon.DeploymentTypeVM:
		switch in.ImageType {
		case edgeproto.ImageType_IMAGE_TYPE_OVA:
			am.PackageType = nbi.OVA
		case edgeproto.ImageType_IMAGE_TYPE_QCOW:
			am.PackageType = nbi.QCOW2
		default:
			return nil, fmt.Errorf("unsupported image type %s for NBI App", in.ImageType.String())
		}
	}
	appAnnotations := in.AppAnnotations
	if appAnnotations == nil {
		appAnnotations = make(map[string]string)
	}
	if repoType, ok := appAnnotations[NBIAppAnnotationRepoType]; ok {
		switch repoType {
		case NBIAppRepoTypePrivate:
			am.AppRepo.Type = nbi.PRIVATEREPO
		case NBIAppRepoTypePublic:
			am.AppRepo.Type = nbi.PUBLICREPO
		}
	}
	am.AppRepo.ImagePath = in.ImagePath
	cspec := nbi.AppManifest_ComponentSpec{}
	cname := appAnnotations[NBIAppAnnotationComponentName]
	if cname == "" {
		cname = in.Key.Name
	}
	cspec.ComponentName = cname
	ports, err := edgeproto.ParseAppPorts(in.AccessPorts)
	if err != nil {
		return nil, err
	}
	// convert ports
	for _, p := range ports {
		ni := nbi.AppManifest_ComponentSpec_NetworkInterfaces{}
		if p.Proto == dme.LProto_L_PROTO_TCP {
			ni.Protocol = nbi.TCP
		} else if p.Proto == dme.LProto_L_PROTO_UDP {
			ni.Protocol = nbi.UDP
		}
		ni.Port = p.InternalPort
		if p.InternalVisOnly {
			ni.VisibilityType = nbi.VISIBILITYINTERNAL
		} else {
			ni.VisibilityType = nbi.VISIBILITYEXTERNAL
		}
		ni.InterfaceId = p.Id
		if ni.InterfaceId == "" {
			// edgeproto native apps don't always have IDs
			ni.InterfaceId = fmt.Sprintf("%s%d", ni.Protocol, p.InternalPort)
		}
		cspec.NetworkInterfaces = append(cspec.NetworkInterfaces, ni)
	}
	am.ComponentSpec = append(am.ComponentSpec, cspec)

	// convert operating system
	if arch, ok := appAnnotations[NBIAppAnnotationOSArch]; ok {
		os := &nbi.OperatingSystem{}
		os.Architecture = nbi.OperatingSystemArchitecture(arch)
		os.Family = nbi.OperatingSystemFamily(appAnnotations[NBIAppAnnotationOSFamily])
		os.License = nbi.OperatingSystemLicense(appAnnotations[NBIAppAnnotationOSLicense])
		os.Version = nbi.OperatingSystemVersion(appAnnotations[NBIAppAnnotationOSVersion])
		am.OperatingSystem = os
	}
	if in.KubernetesResources != nil {
		kr := nbiKubernetesResources(in.KubernetesResources, !in.AllowServerless)
		am.RequiredResources.FromKubernetesResources(*kr)
	}
	return &am, nil
}

func nbiKubernetesResources(in *edgeproto.KubernetesResources, standalone bool) *nbi.KubernetesResources {
	kr := &nbi.KubernetesResources{
		IsStandalone: standalone,
	}
	if in.CpuPool != nil {
		pool := nbi.KubernetesResources_ApplicationResources_CpuPool{}
		pool.Memory = int(in.CpuPool.TotalMemory)
		pool.NumCPU = int(in.CpuPool.TotalVcpus.Whole)
		pool.Topology.MinNodeCpu = int(in.CpuPool.Topology.MinNodeVcpus)
		pool.Topology.MinNodeMemory = int(in.CpuPool.Topology.MinNodeMemory)
		pool.Topology.MinNumberOfNodes = int(in.CpuPool.Topology.MinNumberOfNodes)
		kr.ApplicationResources.CpuPool = &pool
	}
	if in.GpuPool != nil {
		pool := nbi.KubernetesResources_ApplicationResources_GpuPool{}
		pool.Memory = int(in.CpuPool.TotalMemory)
		pool.NumCPU = int(in.CpuPool.TotalVcpus.Whole)
		pool.Topology.MinNodeCpu = int(in.CpuPool.Topology.MinNodeVcpus)
		pool.Topology.MinNodeMemory = int(in.CpuPool.Topology.MinNodeMemory)
		pool.Topology.MinNumberOfNodes = int(in.CpuPool.Topology.MinNumberOfNodes)
		kr.ApplicationResources.GpuPool = &pool
	}
	kr.InfraKind = nbi.Kubernetes
	if in.MinKubernetesVersion != "" {
		kr.Version = &in.MinKubernetesVersion
	}
	return kr
}

func NBIAppSort(a, b nbi.AppManifest) int {
	akey := a.AppProvider + a.Name
	bkey := b.AppProvider + b.Name
	return strings.Compare(akey, bkey)
}

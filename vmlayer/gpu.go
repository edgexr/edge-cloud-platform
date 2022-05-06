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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/gcs"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type GPUDrivers map[edgeproto.GPUDriverKey][]edgeproto.GPUDriverBuild

const DriverInstallationTimeout = 30 * time.Minute
const GPUOperatorTimeout = 10 * time.Minute
const GPUOperatorNamespace = "gpu-operator-resources"
const GPUOperatorSelector = "app=nvidia-operator-validator"

// Must call GCSClient.Close() when done.
func (v *VMPlatform) getGCSStorageClient(ctx context.Context, gpuDriver *edgeproto.GPUDriver) (*gcs.GCSClient, error) {
	bucketName := gpuDriver.StorageBucketName
	accessApi := v.VMProperties.CommonPf.PlatformConfig.AccessApi
	credsObj, err := accessApi.GetGCSCreds(ctx)
	if err != nil {
		return nil, err
	}
	storageClient, err := gcs.NewClient(ctx, credsObj, bucketName, gcs.LongTimeout)
	if err != nil {
		return nil, fmt.Errorf("Unable to setup GCS client: %v", err)
	}
	return storageClient, nil
}

// Fetches driver package:
//        * From local cache, if package is not corrupted/outdated
//        * else, fetch from cloud
func (v *VMPlatform) getGPUDriverPackagePath(ctx context.Context, storageClient *gcs.GCSClient, build *edgeproto.GPUDriverBuild) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getGPUDriverPackagePath", "build", build)
	// Ensure local cache directory exists
	if _, err := os.Stat(v.CacheDir); os.IsNotExist(err) {
		return "", fmt.Errorf("Missing cache dir")
	}

	fileName := build.StoragePath
	localFilePath := v.CacheDir + "/" + strings.ReplaceAll(fileName, "/", "_")
	_, err := os.Stat(localFilePath)
	if err == nil || !os.IsNotExist(err) {
		// Verify if package is valid and not outdated/corrupted
		md5sum, err := cloudcommon.Md5SumFile(localFilePath)
		if err != nil {
			return "", err
		}
		if build.Md5Sum == md5sum {
			// valid cache file
			return localFilePath, nil
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GPU driver pkg not found/corrupted in local cache, fetch it from GCS", "build.DriverPath", build.DriverPath)
	// In not in local cache or is file corrupted/outdated, then fetch from cloud
	err = storageClient.DownloadObject(ctx, fileName, localFilePath)
	if err != nil {
		return "", fmt.Errorf("Failed to download GPU driver package %s from GCS to %s, %v", fileName, localFilePath, err)
	}
	return localFilePath, nil
}

func (v *VMPlatform) downloadGPUDriverLicenseConfig(ctx context.Context, storageClient *gcs.GCSClient, driverPath, licenseMd5Sum string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "downloadGPUDriverLicenseConfig", "driverPath", driverPath)

	localFilePath := v.CacheDir + "/" + strings.ReplaceAll(driverPath, "/", "_")
	_, err := os.Stat(localFilePath)
	if err == nil || !os.IsNotExist(err) {
		// Verify if license config is valid and not outdated/corrupted
		md5sum, err := cloudcommon.Md5SumFile(localFilePath)
		if err != nil {
			return "", err
		}
		if licenseMd5Sum == md5sum {
			// valid cache file
			return localFilePath, nil
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GPU driver license not found in local cache/is outdated/corrupted, fetch it from GCS", "fileName", driverPath)
	err = storageClient.DownloadObject(ctx, driverPath, localFilePath)
	if err != nil {
		if strings.Contains(err.Error(), gcs.NotFoundError) {
			// license config doesn't exist
			return "", nil
		}
		return "", fmt.Errorf("Failed to download GPU driver license config %s from GCS to %s, %v", driverPath, localFilePath, err)
	}
	return localFilePath, nil
}

// Fetches driver license config:
//        * From local cache
//        * In not in local cache, then fetch from cloud
func (v *VMPlatform) getGPUDriverLicenseConfigPath(ctx context.Context, storageClient *gcs.GCSClient, cloudlet *edgeproto.Cloudlet, driver *edgeproto.GPUDriver) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getGPUDriverLicenseConfigPath", "cloudlet key", cloudlet.Key, "driver", driver)
	// Look in local cache first
	if _, err := os.Stat(v.CacheDir); os.IsNotExist(err) {
		return "", fmt.Errorf("Missing cache dir")
	}
	var localFilePath string
	var err error
	// Use cloudlet specific license config if present
	if cloudlet.GpuConfig.LicenseConfig != "" && cloudlet.LicenseConfigStoragePath != "" {
		localFilePath, err = v.downloadGPUDriverLicenseConfig(ctx, storageClient, cloudlet.LicenseConfigStoragePath, cloudlet.GpuConfig.LicenseConfigMd5Sum)
		if err != nil {
			return "", err
		}
	}
	// Use gpu driver license config
	if localFilePath == "" {
		localFilePath, err = v.downloadGPUDriverLicenseConfig(ctx, storageClient, driver.LicenseConfigStoragePath, driver.LicenseConfigMd5Sum)
		if err != nil {
			return "", err
		}
	}
	return localFilePath, nil
}

func (v *VMPlatform) setupGPUDrivers(ctx context.Context, rootLBClient ssh.Client, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, action ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setupGPUDrivers", "clusterInst", clusterInst.Key)
	cloudlet, err := v.GetCloudlet(ctx)
	if err != nil {
		return err
	}
	gpuDriver, err := v.GetCloudletGPUDriver(ctx)
	if err != nil {
		return err
	}
	if gpuDriver == nil {
		return fmt.Errorf("No GPU driver associated with cloudlet %s", clusterInst.Key.CloudletKey)
	}

	updateCallback(edgeproto.UpdateTask, "Setting up GPU drivers on all cluster nodes")

	targetNodes := []string{}
	switch clusterInst.Deployment {
	case cloudcommon.DeploymentTypeDocker:
		targetNodes = append(targetNodes, GetClusterMasterName(ctx, clusterInst))
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		if clusterInst.MasterNodeFlavor == clusterInst.NodeFlavor {
			targetNodes = append(targetNodes, GetClusterMasterName(ctx, clusterInst))
		}
		for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
			targetNodes = append(targetNodes, GetClusterNodeName(ctx, clusterInst, nn))
		}
	default:
		return fmt.Errorf("GPU driver installation not supported for deployment type %s", clusterInst.Deployment)
	}
	storageClient, err := v.getGCSStorageClient(ctx, gpuDriver)
	if err != nil {
		return err
	}
	defer storageClient.Close()
	wgError := make(chan error)
	wgDone := make(chan bool)
	var wg sync.WaitGroup
	for _, node := range targetNodes {
		vmIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), node)
		if err != nil {
			return err
		}

		client, err := rootLBClient.AddHop(vmIP.ExternalAddr, 22)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func(clientIn ssh.Client, nodeName string, wg *sync.WaitGroup) {
			err = v.installGPUDriverBuild(ctx, storageClient, nodeName, clientIn, cloudlet, gpuDriver, updateCallback)
			if err != nil {
				wgError <- err
				return
			}
			wg.Done()
		}(client, node, &wg)
	}

	go func() {
		wg.Wait()
		close(wgDone)
	}()

	// Wait until either WaitGroup is done or an error is received through the channel
	select {
	case <-wgDone:
		break
	case err := <-wgError:
		return err
	case <-time.After(DriverInstallationTimeout):
		return fmt.Errorf("Timed out installing GPU driver on cluster VMs")
	}
	return nil
}

func (v *VMPlatform) GetCloudlet(ctx context.Context) (*edgeproto.Cloudlet, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudlet")
	if v.Caches == nil {
		return nil, fmt.Errorf("caches is nil")
	}
	var cloudlet edgeproto.Cloudlet
	if !v.Caches.CloudletCache.Get(v.VMProperties.CommonPf.PlatformConfig.CloudletKey, &cloudlet) {
		return nil, fmt.Errorf("Unable to find cloudlet %s", v.VMProperties.CommonPf.PlatformConfig.CloudletKey.String())
	}
	return &cloudlet, nil
}

func (v *VMPlatform) GetCloudletGPUDriver(ctx context.Context) (*edgeproto.GPUDriver, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletGPUDriver")
	if v.GPUConfig.Driver.Name == "" {
		return nil, nil
	}
	if v.Caches == nil {
		return nil, fmt.Errorf("caches is nil")
	}
	var gpuDriver edgeproto.GPUDriver
	if !v.Caches.GPUDriverCache.Get(&v.GPUConfig.Driver, &gpuDriver) {
		return nil, fmt.Errorf("Unable to find GPU driver details for %s", v.GPUConfig.Driver.String())
	}
	return &gpuDriver, nil
}

func (v *VMPlatform) installGPUDriverBuild(ctx context.Context, storageClient *gcs.GCSClient, nodeName string, client ssh.Client, cloudlet *edgeproto.Cloudlet, driver *edgeproto.GPUDriver, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "installGPUDriverBuild", "nodeName", nodeName, "driver", driver.Key)
	// verify if GPU driver package is already installed
	out, err := client.Output("nvidia-smi -L")
	if err == nil && len(out) > 0 {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("%s: GPU driver is already installed", nodeName))
		return nil
	}
	// fetch linux kernel version
	out, err = client.Output("uname -sr")
	if err != nil {
		return fmt.Errorf("%s, %v", out, err)
	}
	if out == "" {
		return fmt.Errorf("failed to get kernel version for %s", nodeName)
	}
	parts := strings.Fields(out)
	if len(parts) != 2 {
		return fmt.Errorf("invalid kernel version for %s: %s", nodeName, out)
	}
	os := parts[0]
	kernVers := parts[1]
	if os != "Linux" {
		return fmt.Errorf("unsupported os for %s: %s, only Linux is supported for now", nodeName, os)
	}
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("%s: Fetching GPU driver supported for Linux kernel version %s", nodeName, kernVers))
	found := false
	var reqdBuild edgeproto.GPUDriverBuild
	for _, build := range driver.Builds {
		if build.OperatingSystem == edgeproto.OSType_LINUX &&
			build.KernelVersion == kernVers {
			reqdBuild = build
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("Unable to find Linux GPU driver build for kernel version %s, node %s", kernVers, nodeName)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "found matching GPU driver", "nodename", nodeName, "driverkey", driver.Key, "build", reqdBuild.Name)
	// Get path to GPU driver package file
	pkgPath, err := v.getGPUDriverPackagePath(ctx, storageClient, &reqdBuild)
	if err != nil {
		return err
	}
	// Get path to GPU driver license config file
	licenseConfigPath, err := v.getGPUDriverLicenseConfigPath(ctx, storageClient, cloudlet, driver)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("%s: Copying GPU driver %s (%s)", nodeName, driver.Key.Name, reqdBuild.Name))
	// Upload driver and license config to target node
	outPkgPath := "/tmp" + strings.TrimPrefix(pkgPath, v.CacheDir)
	err = infracommon.SCPFilePath(client, pkgPath, outPkgPath)
	if err != nil {
		return fmt.Errorf("Failed to copy GPU driver from %s to %s on cluster node %s, %v", pkgPath, outPkgPath, nodeName, err)
	}
	outLicPath := ""
	if licenseConfigPath != "" {
		outLicPath = "/tmp" + strings.TrimPrefix(licenseConfigPath, v.CacheDir)
		err = infracommon.SCPFilePath(client, licenseConfigPath, outLicPath)
		if err != nil {
			return fmt.Errorf("Failed to copy GPU driver license config from %s to %s on cluster node %s, %v", licenseConfigPath, outLicPath, nodeName, err)
		}
	}
	// Install GPU driver, setup license and verify it
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("%s: Installing GPU driver %s (%s)", nodeName, driver.Key.Name, reqdBuild.Name))
	cmd := fmt.Sprintf(
		"sudo bash /etc/mobiledgex/install-gpu-driver.sh -n %s -d %s",
		driver.Key.Name,
		outPkgPath,
	)
	if licenseConfigPath != "" {
		cmd += " -l " + outLicPath
	}
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("Failed to setup GPU driver: %s, %v", out, err)
	}
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("%s: Successfully installed GPU driver", nodeName))
	return nil
}

var NvidiaGPUOperatorApp = edgeproto.App{
	Key: edgeproto.AppKey{
		Name:         "nvidia-gpu-operator",
		Version:      "v1.7.0",
		Organization: cloudcommon.OrganizationMobiledgeX,
	},
	ImagePath:     "https://nvidia.github.io/gpu-operator:nvidia/gpu-operator",
	Deployment:    cloudcommon.DeploymentTypeHelm,
	DelOpt:        edgeproto.DeleteType_AUTO_DELETE,
	InternalPorts: true,
	Trusted:       true,
	Annotations:   "version=v1.7.0,wait=true,timeout=180s",
	Configs: []*edgeproto.ConfigFile{
		&edgeproto.ConfigFile{
			Kind: edgeproto.AppConfigHelmYaml,
			Config: `driver:
  enabled: false
`,
		},
	},
}

func (v *VMPlatform) manageGPUOperator(ctx context.Context, rootLBClient ssh.Client, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, action ActionType) error {
	appInst := edgeproto.AppInst{}
	appInst.Key.AppKey = NvidiaGPUOperatorApp.Key
	appInst.Key.ClusterInstKey = *clusterInst.Key.Virtual("")
	appInst.Flavor = clusterInst.Flavor

	kubeNames, err := k8smgmt.GetKubeNames(clusterInst, &NvidiaGPUOperatorApp, &appInst)
	if err != nil {
		return fmt.Errorf("Failed to get kubenames: %v", err)
	}
	waitFor := k8smgmt.WaitRunning
	var timeoutErr error
	switch action {
	case ActionCreate:
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setting up GPU operator for k8s cluster"))
		err = k8smgmt.CreateHelmAppInst(ctx, rootLBClient, kubeNames, clusterInst, &NvidiaGPUOperatorApp, &appInst)
		if err != nil {
			return err
		}
		waitFor = k8smgmt.WaitRunning
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Waiting for GPU operator validations to finish"))
		timeoutErr = fmt.Errorf("Timed out waiting for NVIDIA GPU operator pods to be online")
	case ActionDelete:
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Cleaning up GPU operator for k8s cluster"))
		err = k8smgmt.DeleteHelmAppInst(ctx, rootLBClient, kubeNames, clusterInst)
		if err != nil {
			return err
		}
		err = CleanupGPUOperatorConfigs(ctx, rootLBClient)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to cleanup GPU operator configs", "err", err)
		}
		waitFor = k8smgmt.WaitDeleted
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Waiting for GPU operator resources to be cleaned up"))
		timeoutErr = fmt.Errorf("Timed out waiting for NVIDIA GPU operator pods to be deleted")
	default:
		return nil
	}
	start := time.Now()
	for {
		done, err := k8smgmt.CheckPodsStatus(ctx, rootLBClient, kubeNames.KconfEnv, GPUOperatorNamespace, GPUOperatorSelector, waitFor, start)
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

func CleanupGPUOperatorConfigs(ctx context.Context, client ssh.Client) error {
	gpuOperatorHelmAppName := k8smgmt.NormalizeName(NvidiaGPUOperatorApp.Key.Name)
	return k8smgmt.CleanupHelmConfigs(ctx, client, gpuOperatorHelmAppName)
}

package vmlayer

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/gcs"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type GPUDrivers map[edgeproto.GPUDriverKey][]edgeproto.GPUDriverBuild

const DriverInstallationTimeout = 30 * time.Minute

// Must call GCSClient.Close() when done.
func (v *VMPlatform) getGCSStorageClient(ctx context.Context) (*gcs.GCSClient, error) {
	deploymentTag := v.VMProperties.GetDeploymentTag()
	bucketName := cloudcommon.GetGPUDriverBucketName(deploymentTag)
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
//        * From local cache
//        * In not in local cache, then fetch from cloud
func (v *VMPlatform) getGPUDriverPackagePath(ctx context.Context, storageClient *gcs.GCSClient, build *edgeproto.GPUDriverBuild) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getGPUDriverPackagePath", "build", build)
	// Look in local cache first
	if _, err := os.Stat(v.CacheDir); os.IsNotExist(err) {
		return "", fmt.Errorf("Missing cache dir")
	}

	fileName := cloudcommon.GetGPUDriverBuildPathFromURL(build.DriverPath, v.VMProperties.GetDeploymentTag())
	localFilePath := v.CacheDir + "/" + strings.ReplaceAll(fileName, "/", "_")
	if _, err := os.Stat(localFilePath); os.IsNotExist(err) {
		log.SpanLog(ctx, log.DebugLevelInfra, "GPU driver pkg not found in local cache, fetch it from GCS", "build.DriverPath", build.DriverPath)
		// In not in local cache, then fetch from cloud
		outBytes, err := storageClient.DownloadObject(ctx, fileName)
		if err != nil {
			return "", fmt.Errorf("Failed to download GPU driver package %s from GCS %v", fileName, err)
		}
		err = ioutil.WriteFile(localFilePath, outBytes, 0644)
		if err != nil {
			return "", fmt.Errorf("Failed to create local cache file %s, %v", localFilePath, err)
		}
	}
	return localFilePath, nil
}

// Fetches driver license config:
//        * From local cache
//        * In not in local cache, then fetch from cloud
func (v *VMPlatform) getGPUDriverLicenseConfigPath(ctx context.Context, storageClient *gcs.GCSClient, driverKey *edgeproto.GPUDriverKey) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getGPUDriverLicenseConfigPath", "driverKey", driverKey)
	// Look in local cache first
	if _, err := os.Stat(v.CacheDir); os.IsNotExist(err) {
		return "", fmt.Errorf("Missing cache dir")
	}
	fileName := cloudcommon.GetGPUDriverLicenseStoragePath(driverKey)
	localFilePath := v.CacheDir + "/" + strings.ReplaceAll(fileName, "/", "_")
	if _, err := os.Stat(localFilePath); os.IsNotExist(err) {
		log.SpanLog(ctx, log.DebugLevelInfra, "GPU driver license not found in local cache, fetch it from GCS", "fileName", fileName)
		outBytes, err := storageClient.DownloadObject(ctx, fileName)
		if err != nil {
			if strings.Contains(err.Error(), gcs.NotFoundError) {
				// license config doesn't exist
				return "", nil
			}
			return "", fmt.Errorf("Failed to download GPU driver license config %s from GCS %v", fileName, err)
		}
		err = ioutil.WriteFile(localFilePath, outBytes, 0644)
		if err != nil {
			return "", fmt.Errorf("Failed to create local cache file %s, %v", localFilePath, err)
		}
	}
	return localFilePath, nil
}

func (v *VMPlatform) setupGPUDrivers(ctx context.Context, rootLBClient ssh.Client, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, action ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setupGPUDrivers", "clusterInst", clusterInst.Key)
	updateCallback(edgeproto.UpdateTask, "Setting up GPU drivers on all cluster nodes")
	gpuDriver, err := v.GetCloudletGPUDriver(ctx)
	if err != nil {
		return err
	}
	if gpuDriver == nil {
		// GPU not supported on this cloudlet, just return
		return nil
	}

	targetNodes := []string{}
	switch clusterInst.Deployment {
	case cloudcommon.DeploymentTypeDocker:
		targetNodes = append(targetNodes, GetClusterMasterName(ctx, clusterInst))
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		targetNodes = append(targetNodes, GetClusterMasterName(ctx, clusterInst))
		for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
			targetNodes = append(targetNodes, GetClusterNodeName(ctx, clusterInst, nn))
		}
	default:
		return fmt.Errorf("GPU driver installation not supported for deployment type %s", clusterInst.Deployment)
	}
	storageClient, err := v.getGCSStorageClient(ctx)
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
			err = v.installGPUDriverBuild(ctx, storageClient, nodeName, clientIn, gpuDriver, updateCallback)
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
		close(wgError)
		return err
	case <-time.After(DriverInstallationTimeout):
		return fmt.Errorf("Timed out installing GPU driver on cluster VMs")
	}
	return nil
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

func (v *VMPlatform) installGPUDriverBuild(ctx context.Context, storageClient *gcs.GCSClient, nodeName string, client ssh.Client, driver *edgeproto.GPUDriver, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "installGPUDriverBuild", "nodeName", nodeName, "driver", driver.Key)
	// fetch linux kernel version
	out, err := client.Output("uname -sr")
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
	licenseConfigPath, err := v.getGPUDriverLicenseConfigPath(ctx, storageClient, &driver.Key)
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
		"sudo bash /etc/mobiledgex/install-gpu-driver.sh -n %s -d %s -t %s",
		driver.Key.Name,
		outPkgPath,
		edgeproto.GPUType_CamelName[int32(v.GPUConfig.GpuType)],
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

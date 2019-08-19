package openstack

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/flavor"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const (
	// Platform services
	ServiceTypeCRM      = "crmserver"
	ServiceTypeShepherd = "shepherd"
	PlatformMaxWait     = 10 * time.Second
)

func getPlatformVMName(cloudlet *edgeproto.Cloudlet) string {
	// Form platform VM name based on cloudletKey
	return cloudlet.Key.Name + "." + cloudlet.Key.OperatorKey.Name + ".pf"
}

func startPlatformService(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, client ssh.Client, serviceType string, updateCallback edgeproto.CacheUpdateCallback, cDone chan error) {
	var service_cmd string
	var envVars *map[string]string
	var err error

	switch serviceType {
	case ServiceTypeShepherd:
		service_cmd, envVars, err = intprocess.GetShepherdCmd(cloudlet, pfConfig)
		if err != nil {
			cDone <- fmt.Errorf("Unable to get shepherd service command: %v", err)
			return
		}

	case ServiceTypeCRM:
		service_cmd, envVars, err = cloudcommon.GetCRMCmd(cloudlet, pfConfig)
		if err != nil {
			cDone <- fmt.Errorf("Unable to get crm service command: %v", err)
			return
		}
	default:
		cDone <- fmt.Errorf("Unsupported service type: %s", serviceType)
		return
	}

	// Form platform VM name based on cloudletKey
	platform_vm_name := getPlatformVMName(cloudlet)

	// Pull docker image and start service
	updateCallback(edgeproto.UpdateTask, "Starting "+serviceType)

	var envVarsAr []string
	for k, v := range *envVars {
		envVarsAr = append(envVarsAr, "-e")
		envVarsAr = append(envVarsAr, k+"="+v)
	}
	cmd := []string{
		"sudo docker run",
		"-d",
		"-v /tmp:/tmp",
		"--restart=unless-stopped",
		"--name", platform_vm_name,
		strings.Join(envVarsAr, " "),
		pfConfig.RegistryPath + ":" + pfConfig.PlatformTag,
		service_cmd,
	}
	if out, err := client.Output(strings.Join(cmd, " ")); err != nil {
		cDone <- fmt.Errorf("Unable to start %s: %v, %s\n", serviceType, err, out)
		return
	}

	// - Wait for docker container to start running
	// - And also monitor the UP state for PlatformMaxTime to
	//   catch early Fatal Logs
	// - After which controller will monitor it using CloudletInfo
	start := time.Now()
	for {
		out, err := client.Output(`sudo docker ps -a -n 1 --filter name=` + platform_vm_name + ` --format '{{.Status}}'`)
		if err != nil {
			cDone <- fmt.Errorf("Unable to fetch %s container status: %v, %s\n", serviceType, err, out)
			return
		}
		if strings.Contains(out, "Up ") {
			break
		} else if !strings.Contains(out, "Created") {
			// container exited in failure state
			// Show Fatal Log, if not Fatal log found, then show last 10 lines of error
			out, err = client.Output(`sudo docker logs ` + platform_vm_name + ` 2>&1 | grep FATAL | awk '{for (i=1; i<=NF-3; i++) $i = $(i+3); NF-=3; print}'`)
			if err != nil || out == "" {
				out, err = client.Output(`sudo docker logs ` + platform_vm_name + ` 2>&1 | tail -n 10`)
				if err != nil {
					cDone <- fmt.Errorf("Failed to bringup %s: %s", serviceType, err.Error())
					return
				}
			}
			cDone <- fmt.Errorf("Failed to bringup %s: %s", serviceType, out)
			return
		}
		elapsed := time.Since(start)
		if elapsed >= (PlatformMaxWait) {
			// no issues in wait time
			break
		}
		time.Sleep(1 * time.Second)
	}
	cDone <- nil
	return
}

func (s *Platform) CreateCloudlet(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error

	log.DebugLog(log.DebugLevelMexos, "Creating cloudlet", "cloudletName", cloudlet.Key.Name)

	// Soure OpenRC file to access openstack API endpoint
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Sourcing platform variables for %s cloudlet", cloudlet.PhysicalName))
	err = mexos.InitOpenstackProps(cloudlet.Key.OperatorKey.Name, cloudlet.PhysicalName, pfConfig.VaultAddr)
	if err != nil {
		return err
	}

	// Get Closest Platform Flavor
	finfo, err := mexos.GetFlavorInfo()
	if err != nil {
		return err
	}
	platform_flavor_name, err := flavor.GetClosestFlavor(finfo, *pfFlavor)
	if err != nil {
		return fmt.Errorf("unable to find closest flavor for platform: %v", err)
	}

	// Fetch platform base image name and md5sum
	pfImageName, err := cloudcommon.GetFileName(pfConfig.ImagePath)
	if err != nil {
		return err
	}
	_, md5Sum, err := mexos.GetUrlInfo(pfConfig.ImagePath)
	if err != nil {
		return err
	}

	// Use PlatformBaseImage, if not present then fetch it from MobiledgeX VM registry
	imageDetail, err := mexos.GetImageDetail(pfImageName)
	if err == nil && imageDetail.Status != "active" {
		return fmt.Errorf("image %s is not active", pfImageName)
	}
	if err != nil {
		// Download platform base image and Add to Openstack Glance
		updateCallback(edgeproto.UpdateTask, "Downloading platform base image: "+pfImageName)
		err = mexos.CreateImageFromUrl(pfImageName, pfConfig.ImagePath, md5Sum)
		if err != nil {
			return fmt.Errorf("Error downloading platform base image: %v", err)
		}
	}

	// Form platform VM name based on cloudletKey
	platform_vm_name := getPlatformVMName(cloudlet)

	// Generate SSH KeyPair
	keyPairPath := "/tmp/" + platform_vm_name
	pubKey, _, err := ssh.GetKeyPair(keyPairPath)
	if err != nil {
		return err
	}

	// Use cloud-config to configure SSH access
	cloud_config := `#cloud-config
bootcmd:
 - echo MOBILEDGEX PLATFORM CLOUD CONFIG START
 - echo 'APT::Periodic::Enable "0";' > /etc/apt/apt.conf.d/10cloudinit-disable
hostname: ` + cloudlet.Key.Name + `
chpasswd: { expire: False }
ssh_pwauth: False
timezone: UTC
ssh_authorized_keys:
 - ` + pubKey

	// TODO Upload SSHKeyPair to Vault so that all the VMs in the cloudlet use this KeyPair

	vmp, err := mexos.GetVMParams(
		mexos.UserVMDeployment,
		platform_vm_name,
		platform_flavor_name,
		pfImageName,
		"",           // AuthPublicKey
		"tcp:22",     // AccessPorts
		cloud_config, // DeploymentManifest,
		"",           // Command,
		nil,          // NetSpecInfo
	)
	if err != nil {
		return fmt.Errorf("unable to get vm params: %v", err)
	}

	// Gather registry credentails from Vault
	updateCallback(edgeproto.UpdateTask, "Fetching registry auth credentials")
	regAuth, err := cloudcommon.GetRegistryAuth(pfConfig.RegistryPath, pfConfig.VaultAddr)
	if err != nil {
		return fmt.Errorf("unable to fetch registry auth credentials")
	}
	if regAuth.AuthType != cloudcommon.BasicAuth {
		return fmt.Errorf("unsupported registry auth type %s", regAuth.AuthType)
	}

	// Deploy Platform VM
	updateCallback(edgeproto.UpdateTask, "Deploying Platform VM")
	log.DebugLog(log.DebugLevelMexos, "Deploying VM", "stackName", platform_vm_name, "flavor", platform_flavor_name)
	err = mexos.CreateHeatStackFromTemplate(vmp, platform_vm_name, mexos.VmTemplate, updateCallback)
	if err != nil {
		return fmt.Errorf("CreateVMAppInst error: %v", err)
	}
	updateCallback(edgeproto.UpdateTask, "Successfully Deployed Platform VM")

	// Fetch external IP for further configuration
	external_ip, err := mexos.GetServerIPAddr(mexos.GetCloudletExternalNetwork(), platform_vm_name)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Platform VM external IP: "+external_ip)
	log.DebugLog(log.DebugLevelMexos, "external IP", "ip", external_ip)

	// Setup SSH Client
	auth := ssh.Auth{Keys: []string{keyPairPath}}
	gwaddr, gwport := mexos.GetCloudletCRMGatewayIPAndPort()
	client, err := ssh.NewNativeClient("ubuntu", external_ip, "SSH-2.0-mobiledgex-ssh-client-1.0", 22, gwaddr, gwport, &auth, &auth, nil)
	if err != nil {
		return fmt.Errorf("cannot get ssh client for server %s with ip %s, %v", platform_vm_name, external_ip, err)
	}

	// Verify if controller's notify port is reachable
	updateCallback(edgeproto.UpdateTask, "Verifying if controller notification channel is reachable")
	addrPort := strings.Split(pfConfig.NotifyCtrlAddrs, ":")
	if len(addrPort) != 2 {
		return fmt.Errorf("notifyctrladdrs format is incorrect")
	}
	if out, err := client.Output(
		fmt.Sprintf(
			"nc %s %s -w 5", addrPort[0], addrPort[1],
		),
	); err != nil {
		return fmt.Errorf("controller's notify port is unreachable: %v, %s\n", err, out)
	}

	// Verify if Openstack API Endpoint is reachable
	updateCallback(edgeproto.UpdateTask, "Verifying if Openstack API Endpoint is reachable")
	osAuthUrl := os.Getenv("OS_AUTH_URL")
	if osAuthUrl == "" {
		return fmt.Errorf("unable to find OS_AUTH_URL")
	}
	urlObj, err := url.Parse(osAuthUrl)
	if err != nil {
		return fmt.Errorf("unable to parse OS_AUTH_URL: %s, %v\n", osAuthUrl, err)
	}
	if _, err := client.Output(
		fmt.Sprintf(
			"nc %s %s -w 5", urlObj.Hostname(), urlObj.Port(),
		),
	); err != nil {
		updateCallback(edgeproto.UpdateTask, "Adding route for API endpoint as it is unreachable")
		// Fetch gateway IP of external network
		gatewayAddr, err := mexos.GetExternalGateway(mexos.GetCloudletExternalNetwork())
		if err != nil {
			return fmt.Errorf("unable to fetch gateway IP for external network: %s, %v",
				mexos.GetCloudletExternalNetwork(), err)
		}
		// Add route to reach API endpoint
		if out, err := client.Output(
			fmt.Sprintf(
				"sudo route add -host %s gw %s", urlObj.Hostname(), gatewayAddr,
			),
		); err != nil {
			return fmt.Errorf("unable to add route to reach API endpoint: %v, %s\n", err, out)
		}
		// Retry
		updateCallback(edgeproto.UpdateTask, "Retrying verification of reachability of Openstack API endpoint")
		if out, err := client.Output(
			fmt.Sprintf(
				"nc %s %s -w 5", urlObj.Hostname(), urlObj.Port(),
			),
		); err != nil {
			return fmt.Errorf("Openstack API Endpoint is unreachable: %v, %s\n", err, out)
		}
	}

	// NOTE: Once we have certs per service support following copy will not be required
	// Upload server certs i.e. crt, key, ca.crt files to Platform VM
	updateCallback(edgeproto.UpdateTask, "Uploading TLS certs to platform VM")
	dir, crtFile := filepath.Split(pfConfig.TlsCertFile)

	ext := filepath.Ext(crtFile)
	if ext == "" {
		return fmt.Errorf("invalid tls cert file name: %s", crtFile)
	}
	keyPath := dir + strings.TrimSuffix(crtFile, ext) + ".key"

	copyFiles := []string{
		pfConfig.TlsCertFile,
		keyPath,
	}

	matches, err := filepath.Glob(dir + "*-ca.crt")
	if err != nil {
		return fmt.Errorf("unable to find ca crt file")
	}
	for _, match := range matches {
		copyFiles = append(copyFiles, match)
	}

	for _, copyFile := range copyFiles {
		err = mexos.SCPFilePath(client, copyFile, "/tmp/")
		if err != nil {
			return fmt.Errorf("error copying %s to platform VM", copyFile)
		}
	}
	pfConfig.TlsCertFile = "/tmp/" + crtFile

	// Login to docker registry
	updateCallback(edgeproto.UpdateTask, "Setting up docker registry")
	if out, err := client.Output(
		fmt.Sprintf(
			`echo "%s" | sudo docker login -u %s --password-stdin %s`,
			regAuth.Password,
			regAuth.Username,
			pfConfig.RegistryPath,
		),
	); err != nil {
		return fmt.Errorf("unable to login to docker registry: %v, %s\n", err, out)
	}

	// setup SSH access to cloudlet for CRM
	updateCallback(edgeproto.UpdateTask, "Setting up security group for SSH access")
	groupName := mexos.GetCloudletSecurityGroup()
	if err := mexos.AddSecurityRuleCIDR(external_ip, "tcp", groupName, "22"); err != nil {
		return fmt.Errorf("unable to add security rule for ssh access, err: %v", err)
	}

	// Start platform service on PlatformVM
	crmChan := make(chan error, 1)
	shepherdChan := make(chan error, 1)
	go startPlatformService(cloudlet, pfConfig, client, ServiceTypeCRM, updateCallback, crmChan)
	go startPlatformService(cloudlet, pfConfig, client, ServiceTypeShepherd, updateCallback, shepherdChan)
	// Wait for platform services to come up
	crmErr := <-crmChan
	shepherdErr := <-shepherdChan
	if crmErr != nil {
		return crmErr
	}
	return shepherdErr
}

func (s *Platform) DeleteCloudlet(cloudlet *edgeproto.Cloudlet) error {
	log.DebugLog(log.DebugLevelMexos, "Deleting cloudlet", "cloudletName", cloudlet.Key.Name)
	platform_vm_name := getPlatformVMName(cloudlet)
	err := mexos.HeatDeleteStack(platform_vm_name)
	if err != nil {
		return fmt.Errorf("DeleteCloudlet error: %v", err)
	}
	return nil
}

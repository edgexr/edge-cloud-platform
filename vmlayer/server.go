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
	"sync"
	"time"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type CacheOption bool

const UseCache CacheOption = true
const NoCache CacheOption = false

var serverCacheLock sync.Mutex

// map of group name to server name to ip
var serverExternalIpCache map[string]*ServerIP

const ServerDoesNotExistError string = "Server does not exist"
const ServerIPNotFound string = "unable to find IP"

var ServerActive = "ACTIVE"
var ServerShutoff = "SHUTOFF"

var ActionStart = "start"
var ActionStop = "stop"
var ActionReboot = "reboot"

type ServerDetail struct {
	Addresses []ServerIP
	ID        string
	Name      string
	Status    string
}

type VMUpdateList struct {
	CurrentVMs  (map[string]string)
	NewVMs      (map[string]*VMOrchestrationParams)
	VmsToCreate (map[string]*VMOrchestrationParams)
	VmsToDelete (map[string]string)
}

func init() {
	serverExternalIpCache = make(map[string]*ServerIP)
}

// GetIPFromServerName returns the IP for the givens serverName, on either the network or subnetName.  Optionally lookup and
// store to cache can be specified
func (v *VMPlatform) GetIPFromServerName(ctx context.Context, networkName, subnetName, serverName string, ops ...pc.SSHClientOp) (*ServerIP, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerName", "networkName", networkName, "subnetName", subnetName, "serverName", serverName)
	opts := pc.SSHOptions{}
	opts.Apply(ops)
	isExtNet := networkName == v.VMProperties.GetCloudletExternalNetwork()
	if isExtNet && opts.CachedIP {
		sip := GetServerIPFromCache(ctx, serverName)
		if sip != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerName found ip in cache", "serverName", serverName, "sip", sip)
			return sip, nil
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerName did not find ip in cache", "serverName", serverName)
		}
	}
	portName := ""
	if subnetName != "" {
		portName = GetPortName(serverName, subnetName)
	}
	sd, err := v.VMProvider.GetServerDetail(ctx, serverName)
	if err != nil {
		return nil, err
	}
	sip, err := GetIPFromServerDetails(ctx, networkName, portName, sd)
	if err == nil && isExtNet && opts.CachedIP {
		AddServerExternalIpToCache(ctx, serverName, sip)
	}
	return sip, err
}

func GetIPFromServerDetails(ctx context.Context, networkName string, portName string, sd *ServerDetail) (*ServerIP, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerDetails", "server", sd.Name, "networkName", networkName, "portName", portName, "serverDetail", sd)
	var sipPtr *ServerIP
	netFound := false
	portFound := false
	for i, s := range sd.Addresses {
		// with the new common shared network in some platforms (currently VCD) combined with preexisting legacy pre-common networks there is a chance
		// for multiple ips to be found, once with the port and once with the network. If this happens, give preference networks found via the port name
		// which is more specific
		if networkName != "" && s.Network == networkName {
			if netFound {
				log.SpanLog(ctx, log.DebugLevelInfra, "Error: GetIPFromServerDetails found multiple matches via network", "networkName", networkName, "portName", portName, "serverDetail", sd)
				return nil, fmt.Errorf("Multiple IP addresses found for server: %s on same network: %s", sd.Name, networkName)
			}
			netFound = true
			if portFound {
				log.SpanLog(ctx, log.DebugLevelInfra, "prioritizing IP address previously found via port", "networkName", networkName, "portName", portName, "serverDetail", sd)
			} else {
				sipPtr = &sd.Addresses[i]
			}
		}
		if portName != "" && s.PortName == portName {
			if portFound {
				// this indicates we passed in multiple parameters that found an IP.  For example, an external network name plus an internal port name
				log.SpanLog(ctx, log.DebugLevelInfra, "Error: GetIPFromServerDetails found multiple matches via port", "networkName", networkName, "portName", portName, "serverDetail", sd)
				return nil, fmt.Errorf("Multiple IP addresses found for server: %s on same port: %s", sd.Name, portName)
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerDetails found match", "serverAddress", s)
			portFound = true
			sipPtr = &sd.Addresses[i]
		}
	}
	if portFound || netFound {
		return sipPtr, nil
	}
	return nil, fmt.Errorf(ServerIPNotFound+" for server: %s on network: %s port: %s", sd.Name, networkName, portName)
}

func GetCloudletNetworkIfaceFile() string {
	return "/etc/netplan/50-cloud-init.yaml"
}

func (v *VMPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return "", err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeVM:
		return v.VMProvider.GetConsoleUrl(ctx, appInst.UniqueId)
	default:
		return "", fmt.Errorf("unsupported deployment type %s", deployment)
	}
}

func (v *VMPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	PowerState := appInst.PowerState

	var result OperationInitResult
	var err error
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeVM:
		serverName := appInst.UniqueId
		fqdn := appInst.Uri
		log.SpanLog(ctx, log.DebugLevelInfra, "setting server state", "serverName", serverName, "fqdn", fqdn, "PowerState", PowerState)

		updateCallback(edgeproto.UpdateTask, "Verifying AppInst state")
		serverDetail, err := v.VMProvider.GetServerDetail(ctx, serverName)
		if err != nil {
			return err
		}

		serverAction := ""
		switch PowerState {
		case edgeproto.PowerState_POWER_ON_REQUESTED:
			if serverDetail.Status == ServerActive {
				return fmt.Errorf("server %s is already active", serverName)
			}
			serverAction = ActionStart
		case edgeproto.PowerState_POWER_OFF_REQUESTED:
			if serverDetail.Status == ServerShutoff {
				return fmt.Errorf("server %s is already stopped", serverName)
			}
			serverAction = ActionStop
		case edgeproto.PowerState_REBOOT_REQUESTED:
			serverAction = ActionReboot
			if serverDetail.Status != ServerActive {
				return fmt.Errorf("server %s is not active", serverName)
			}
		default:
			return fmt.Errorf("unsupported server power action: %s", PowerState)
		}

		serverSubnet := v.VMProperties.GetCloudletExternalNetwork()
		if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
			serverSubnet = serverName + "-subnet"
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Fetching external address of %s", serverName))
		oldServerIP, err := GetIPFromServerDetails(ctx, serverSubnet, "", serverDetail)
		if err != nil || oldServerIP.ExternalAddr == "" {
			return fmt.Errorf("unable to fetch external ip for %s, addr %s, err %v", serverName, serverSubnet, err)
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Performing action %s on %s", serverAction, serverName))
		err = v.VMProvider.SetPowerState(ctx, serverName, serverAction)
		if err != nil {
			return err
		}

		if PowerState == edgeproto.PowerState_POWER_ON_REQUESTED || PowerState == edgeproto.PowerState_REBOOT_REQUESTED {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Waiting for server %s to become active", serverName))
			serverDetail, err := v.VMProvider.GetServerDetail(ctx, serverName)
			if err != nil {
				return err
			}
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Fetching external address of %s", serverName))
			newServerIP, err := GetIPFromServerDetails(ctx, serverSubnet, "", serverDetail)
			if err != nil || newServerIP.ExternalAddr == "" {
				return fmt.Errorf("unable to fetch external ip for %s, addr %s, err %v", serverName, serverSubnet, err)
			}
			if oldServerIP.ExternalAddr != newServerIP.ExternalAddr {
				// IP changed, update DNS entry
				updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Updating DNS entry as IP changed for %s", serverName))
				log.SpanLog(ctx, log.DebugLevelInfra, "updating DNS entry", "serverName", serverName, "fqdn", fqdn, "ip", newServerIP)
				err = v.VMProperties.CommonPf.ActivateFQDNA(ctx, fqdn, newServerIP.ExternalAddr)
				if err != nil {
					return fmt.Errorf("unable to update fqdn for %s, addr %s, err %v", serverName, newServerIP.ExternalAddr, err)
				}
			}
		}
		updateCallback(edgeproto.UpdateTask, "Performed power control action successfully")
	default:
		return fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return nil
}

// WaitServerReady waits up to the specified duration for the server to be reachable via SSH
// and pass any additional checks from the provider
func WaitServerReady(ctx context.Context, provider VMProvider, client ssh.Client, server string, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WaitServerReady", "server", server)
	start := time.Now()
	for {
		out, err := client.Output("sudo grep 'Finished mobiledgex init' /var/log/mobiledgex.log")
		log.SpanLog(ctx, log.DebugLevelInfra, "grep Finished mobiledgex init result", "out", out, "err", err)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Server has completed mobiledgex init", "server", server)
			// perform any additional checks from the provider
			err = provider.CheckServerReady(ctx, client, server)
			log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady result", "err", err)
			if err == nil {
				break
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "server not ready", "err", err)
		elapsed := time.Since(start)
		if elapsed > timeout {
			return fmt.Errorf("timed out waiting for VM %s", server)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "sleeping 10 seconds before retry", "elapsed", elapsed, "timeout", timeout)
		time.Sleep(10 * time.Second)

	}
	log.SpanLog(ctx, log.DebugLevelInfra, "WaitServerReady OK", "server", server)
	return nil
}

func GetServerIPFromCache(ctx context.Context, serverName string) *ServerIP {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerIPFromCache", "serverName", serverName)
	serverCacheLock.Lock()
	defer serverCacheLock.Unlock()
	return serverExternalIpCache[serverName]
}

func AddServerExternalIpToCache(ctx context.Context, serverName string, sip *ServerIP) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddServerExternalIpToCache", "serverName", serverName)
	serverCacheLock.Lock()
	defer serverCacheLock.Unlock()
	serverExternalIpCache[serverName] = sip
}

func DeleteServerIpFromCache(ctx context.Context, serverName string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteServerIpFromCache", "serverName", serverName)
	serverCacheLock.Lock()
	defer serverCacheLock.Unlock()
	delete(serverExternalIpCache, serverName)
}

func GetVmwareMappedOsType(osType edgeproto.VmAppOsType) (string, error) {
	switch osType {
	case edgeproto.VmAppOsType_VM_APP_OS_UNKNOWN:
		return "otherGuest64", nil
	case edgeproto.VmAppOsType_VM_APP_OS_LINUX:
		return "otherLinux64Guest", nil
	case edgeproto.VmAppOsType_VM_APP_OS_WINDOWS_10:
		return "windows9_64Guest", nil
	case edgeproto.VmAppOsType_VM_APP_OS_WINDOWS_2012:
		return "windows8Server64Guest", nil
	case edgeproto.VmAppOsType_VM_APP_OS_WINDOWS_2016:
		fallthrough // shows as 2016 in vcenter
	case edgeproto.VmAppOsType_VM_APP_OS_WINDOWS_2019:
		return "windows9Server64Guest", nil
	}
	return "", fmt.Errorf("Invalid value for VmAppOsType %v", osType)
}

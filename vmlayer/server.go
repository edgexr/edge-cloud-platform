package vmlayer

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type NetworkType string

const ServerDoesNotExistError string = "Server does not exist"

var ServerActive = "ACTIVE"
var ServerShutoff = "SHUTOFF"

type ServerDetail struct {
	Addresses []ServerIP
	ID        string
	Name      string
	Status    string
}

func GetIPFromServerDetails(ctx context.Context, networkName string, portName string, sd *ServerDetail) (*ServerIP, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerDetails", "networkName", networkName, "portName", portName, "serverDetail", sd)
	for _, s := range sd.Addresses {
		if (networkName != "" && s.Network == networkName) || (portName != "" && s.PortName == portName) {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("unable to find IP for server: %s on network: %s port: %s", sd.Name, networkName, portName)
}

func GetCloudletNetworkIfaceFile() string {
	return "/etc/network/interfaces.d/50-cloud-init.cfg"
}

func (v *VMPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeVM:
		objName := cloudcommon.GetAppFQN(&app.Key)
		return v.VMProvider.GetConsoleUrl(ctx, objName)
	default:
		return "", fmt.Errorf("unsupported deployment type %s", deployment)
	}
}

func (v *VMPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	PowerState := appInst.PowerState
	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeVM:
		serverName := cloudcommon.GetAppFQN(&app.Key)
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
			if serverDetail.Status == "ACTIVE" {
				return fmt.Errorf("server %s is already active", serverName)
			}
			serverAction = "start"
		case edgeproto.PowerState_POWER_OFF_REQUESTED:
			if serverDetail.Status == "SHUTOFF" {
				return fmt.Errorf("server %s is already stopped", serverName)
			}
			serverAction = "stop"
		case edgeproto.PowerState_REBOOT_REQUESTED:
			serverAction = "reboot"
			if serverDetail.Status != "ACTIVE" {
				return fmt.Errorf("server %s is not active", serverName)
			}
		default:
			return fmt.Errorf("unsupported server power action: %s", PowerState)
		}

		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Fetching external address of %s", serverName))
		oldServerIP, err := GetIPFromServerDetails(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", serverDetail)
		if err != nil || oldServerIP.ExternalAddr == "" {
			return fmt.Errorf("unable to fetch external ip for %s, addr %s, err %v", serverName, v.VMProperties.GetCloudletExternalNetwork(), err)
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
			newServerIP, err := GetIPFromServerDetails(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", serverDetail)
			if err != nil || newServerIP.ExternalAddr == "" {
				return fmt.Errorf("unable to fetch external ip for %s, addr %s, err %v", serverName, v.VMProperties.GetCloudletExternalNetwork(), err)
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

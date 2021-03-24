package vcd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
	"github.com/vmware/go-vcloud-director/v2/govcd"
)

var VCDClientCtxKey = "VCDClientCtxKey"

var NoVCDClientInContext = "No VCD Client in Context"

// vcd security related operations

// physicalname (vault key) not needed when  using insure env vars.
func (v *VcdPlatform) PopulateOrgLoginCredsFromEnv(ctx context.Context) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "PopulateOrgLoginCredsFromEnv")

	creds := VcdConfigParams{
		User:     os.Getenv("VCD_USER"),
		Password: os.Getenv("VCD_PASSWORD"),
		Org:      os.Getenv("VCD_ORG"),
		Href:     os.Getenv("VCD_IP") + "/api",
		VDC:      os.Getenv("VDC_NAME"),
		Insecure: true,
	}
	if creds.User == "" {
		return fmt.Errorf("User not defined")
	}
	if creds.Password == "" {
		return fmt.Errorf("Passwd not defined")
	}
	if creds.Org == "" {
		return fmt.Errorf("Org not defined")
	}
	if creds.Href == "" {
		return fmt.Errorf("Href not defined")
	}
	if creds.VDC == "" {
		return fmt.Errorf("missing VDC name")
	}
	v.Creds = &creds
	return nil
}

func (v *VcdPlatform) GetVcdUser() string {
	return v.Creds.User
}
func (v *VcdPlatform) GetVcdPassword() string {
	return v.Creds.Password
}
func (v *VcdPlatform) GetVcdOrgName() string {
	return v.Creds.Org
}
func (v *VcdPlatform) GetVcdVdcName() string {
	return v.Creds.VDC
}
func (v *VcdPlatform) GetVcdAddress() string {

	return v.Creds.Href
}

// Create new option for our live unit tests to use this rather than env XXX
func (v *VcdPlatform) PopulateOrgLoginCredsFromVault(ctx context.Context) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "PopulateOrgLoginCredsFromVault")
	creds := VcdConfigParams{
		User:     v.GetVCDUser(),
		Password: v.GetVCDPassword(),
		Org:      v.GetVCDORG(),
		Href:     v.GetVCDIP() + "/api",
		VDC:      v.GetVDCName(),
		Insecure: true,
	}

	if creds.User == "" {
		return fmt.Errorf("User not defined")
	}
	if creds.Password == "" {
		return fmt.Errorf("Passwd not defined")
	}
	if creds.Org == "" {
		return fmt.Errorf("Org not defined")
	}
	if creds.Href == "" {
		return fmt.Errorf("Href not defined")
	}
	if creds.VDC == "" {
		return fmt.Errorf("missing VDC name")
	}
	v.Creds = &creds

	log.SpanLog(ctx, log.DebugLevelInfra, "client login creds", "user", creds.User, "Org", creds.Org, "Vdc", creds.VDC, "URI", "creds.Href")

	return nil
}

func (v *VcdPlatform) GetExternalIpNetworkCidr(ctx context.Context, vcdClient *govcd.VCDClient) (string, error) {

	extNet, err := v.GetExtNetwork(ctx, vcdClient)
	if err != nil {
		return "", err
	}

	scope := extNet.OrgVDCNetwork.Configuration.IPScopes.IPScope[0]
	cidr, err := MaskToCidr(scope.Netmask)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalIpNetworkCidr error converting mask to cider", "cidr", cidr, "error", err)
		return "", err
	}
	addr := scope.Gateway + "/" + cidr

	log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalIpNetworkCidr", "addr", addr)

	return addr, nil

}

func (v *VcdPlatform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, trustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB", "rootLBName", rootLBName)
	iptblStart := time.Now()

	// Check if we have any trust policy, and use it if so
	tp, err := v.GetCloudletTrustPolicy(ctx)
	if tp == nil || err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB no TrustPolicy")
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB have TrustPolicy")
		trustPolicy = tp
	}
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB", "rootLBName", rootLBName)
	// configure iptables based security
	sshCidrsAllowed := []string{}
	externalNet, err := v.GetExternalIpNetworkCidr(ctx, vcdClient)
	if err != nil {
		return err
	}
	sshCidrsAllowed = append(sshCidrsAllowed, externalNet)
	err = v.vmProperties.SetupIptablesRulesForRootLB(ctx, client, sshCidrsAllowed, trustPolicy)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB SetupIptableRulesForRootLB failed", "rootLBName", rootLBName, "err", err)
		return err
	}
	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setup Root LB time %s", cloudcommon.FormatDuration(time.Since(iptblStart), 2)))
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB SetupIptableRulesForRootLB complete", "rootLBName", rootLBName, "time", time.Since(iptblStart).String())
	return nil
}

func (v *VcdPlatform) WhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WhitelistSecurityRules", "wlParams", wlParams)
	// this can be called during LB init so we need to ensure we can reach the server before trying iptables commands
	err := vmlayer.WaitServerReady(ctx, v, client, wlParams.ServerName, vmlayer.MaxRootLBWait)
	if err != nil {
		return err
	}
	return infracommon.AddIngressIptablesRules(ctx, client, wlParams.Label, wlParams.AllowedCIDR, wlParams.DestIP, wlParams.Ports)
}

func (v *VcdPlatform) RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveWhitelistSecurityRules", "wlParams", wlParams)
	return infracommon.RemoveIngressIptablesRules(ctx, client, wlParams.Label, wlParams.AllowedCIDR, wlParams.DestIP, wlParams.Ports)
}

func setVer(cli *govcd.VCDClient) error {
	if cli != nil {
		cli.Client.APIVersion = "33.0" // vmwarelab is 10.1
	}
	return nil
}

func (v *VcdPlatform) GetClient(ctx context.Context, creds *VcdConfigParams) (client *govcd.VCDClient, err error) {

	if v.TestMode {
		err := v.PopulateOrgLoginCredsFromEnv(ctx)
		if err != nil {
			return nil, err
		}
	}

	if creds == nil {
		// usually indicates we called GetClient before InitProvider
		return nil, fmt.Errorf("nil creds passed to GetClient")
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "GetClient", "user", creds.User)

	u, err := url.ParseRequestURI(creds.Href)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse request to org %s at %s err: %s", creds.Org, creds.Href, err)
	}
	vcdClient := govcd.NewVCDClient(*u, creds.Insecure)

	if vcdClient.Client.VCDToken != "" {
		_ = vcdClient.SetToken(creds.Org, govcd.AuthorizationHeader, creds.Token)
	} else {
		_, err := vcdClient.GetAuthResponse(creds.User, creds.Password, creds.Org)
		if err != nil {
			return nil, fmt.Errorf("Unable to login to org %s at %s err: %s", creds.Org, creds.Href, err)
		}
		//creds.Token = resp.Header[govcd.AuthorizationHeader]
	}
	// xxx revisit
	// prefer the highest Api version found on the other end.
	// vCD 10.0 == Api 33
	// vCD 10.1 == Api 34
	// The VMware vcd is 10.1 and highest is 34, but if we change it
	// to say 33, we get ENF (entity not found) for our vdc <sigh>
	// So find another way to set this API version. By default,
	// vcdClient.Client.APIVersion == 31.0 which is a 9.5 version.

	// Ok, checkout api_vcd.go, we'd need to adjust the loginURL
	// to match the version change. NewVCDClient could be used with options
	// but 10.1 supports 31.0, so until we care, we don't.
	/*
		if vcdClient.Client.APIVCDMaxVersionIs(">= 33.0") {
			fmt.Printf("APIVCDMaxVersionIs of >= 33.0 is true")
			vcdClient.Client.APIVersion = "33.0"
		}
		if vcdClient.Client.APIClientVersionIs("= 34.0") {
			fmt.Printf("Talking with vCD v10.1 using API v 34.0\n")
			vcdClient.Client.APIVersion = "34.0"
		}
	*/
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClient connected", "API Version", vcdClient.Client.APIVersion)
	// setup the client in the context
	return vcdClient, nil

}

func (v *VcdPlatform) ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {

	errMap := make(map[string]error)
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules", "egressRestricted", egressRestricted, "TrustPolicy", TrustPolicy, "action", action)
	updateCallback(edgeproto.UpdateTask, "Configuring Cloudlet Security Rules for TrustPolicy")
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return fmt.Errorf("GetVdc Failed - %v", err)
	}

	if action == vmlayer.ActionCreate || action == vmlayer.ActionUpdate {
		log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules", "action", action, "Cloudlet secgrp name", v.vmProperties.CloudletSecgrpName)
		vmgp, err := vmlayer.GetVMGroupOrchestrationParamsFromTrustPolicy(ctx, v.vmProperties.CloudletSecgrpName, TrustPolicy, egressRestricted, vmlayer.SecGrpWithAccessPorts("tcp:22", infracommon.RemoteCidrAll))
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules GetVMGroupOrchestartionParmasFromTrustPolicy failed", "error", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules", "action", action, "Cloudlet secgrp name", v.vmProperties.CloudletSecgrpName, "vmgp", vmgp)
		vappRefList := vdc.GetVappList()
		netName := v.vmProperties.GetCloudletExternalNetwork()
		for _, vappRef := range vappRefList {
			vapp, err := vdc.GetVAppByHref(vappRef.HREF)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules GetVAppByHref  failed", "error", err)
				errMap[vappRef.Name] = err
				continue
			}
			ip, err := v.GetAddrOfVapp(ctx, vapp, netName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules GetAddrOfVapp  failed", "error", err)
				continue
			}
			sshClient, err := v.vmProperties.CommonPf.GetSSHClientFromIPAddr(ctx, ip, pc.WithUser(infracommon.SSHUser), pc.WithCachedIp(true))
			if err != nil {
				errMap[vapp.VApp.Name] = err
				log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules GetSSHClientFromIPAddr failed", "error", err)
				continue
			}
			var cidrs []string
			log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules SetupIpTables for", "IP", ip, "sshClient", sshClient)
			err = v.vmProperties.SetupIptablesRulesForRootLB(ctx, sshClient, cidrs, TrustPolicy)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules SetupIptablesRulesForRootLB  failed", "IP", ip, "sshClient", sshClient, "error", err)
				errMap[vapp.VApp.Name] = err
			}
		}

		if len(errMap) != 0 {
			log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules encontered errors:")
			for n, e := range errMap {
				log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules error", "server", n, "error", e)
			}
			return fmt.Errorf("Failure")
		}
	} else {
		// action.delete comes from DeleteCloudlet, rules will go down with the vm
		log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules action.delete noop")
	}

	return nil

}

// GetVcdClientFromContext returns a client object if one exists, otherwise nil
func (v *VcdPlatform) GetVcdClientFromContext(ctx context.Context) *govcd.VCDClient {
	vcdClient, found := ctx.Value(VCDClientCtxKey).(*govcd.VCDClient)
	if !found {
		return nil
	}
	return vcdClient
}

func (v *VcdPlatform) InitOperationContext(ctx context.Context, operationStage vmlayer.OperationInitStage) (context.Context, vmlayer.OperationInitResult, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitOperationContext", "operationStage", operationStage)

	if operationStage == vmlayer.OperationInitStart {
		// getClient will setup the client within the context.  First ensure it is not already set, which
		// indicates an error because we don't want it to be setup twice as it may get cleaned up erroneously.
		// So we look for the client and expect a NoVCDClientInContext error
		vcdClient := v.GetVcdClientFromContext(ctx)
		if vcdClient != nil {
			// This indicates we called InitOperationContext with OperationInitStart twice before OperationInitComplete
			// which is unavoidable in some flows
			log.SpanLog(ctx, log.DebugLevelInfra, "InitOperationContext VCDClient is already in context")
			return ctx, vmlayer.OperationAlreadyInitialized, nil
		}
		// now get a new client
		var err error
		vcdClient, err = v.GetClient(ctx, v.Creds)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to initialize vcdClient", "err", err)
			return ctx, vmlayer.OperationInitFailed, err
		} else {
			ctx = context.WithValue(ctx, VCDClientCtxKey, vcdClient)
			log.SpanLog(ctx, log.DebugLevelInfra, "Updated context with client", "APIVersion", vcdClient.Client.APIVersion, "key", VCDClientCtxKey)
			return ctx, vmlayer.OperationNewlyInitialized, nil
		}
	} else {
		vcdClient := v.GetVcdClientFromContext(ctx)
		if vcdClient == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext, "ctx", fmt.Sprintf("%+v", ctx))
			return ctx, vmlayer.OperationInitFailed, fmt.Errorf(NoVCDClientInContext)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Disconnecting vcdClient")
		err := vcdClient.Disconnect()
		if err != nil {
			// err here happens all the time but has no impact
			if v.Verbose {
				log.SpanLog(ctx, log.DebugLevelInfra, "Disconnect vcdClient", "err", err)
			}
		}
		return ctx, vmlayer.OperationNewlyInitialized, err
	}
}

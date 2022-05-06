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

package vcd

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vmware/go-vcloud-director/v2/govcd"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

var VCDClientCtxKey = "VCDClientCtxKey"

var NoVCDClientInContext = "No VCD Client in Context"

var maxOauthTokenReady = time.Second * 30
var maxOauthTokenFromNotify = time.Minute * 2
var maxOauthRefreshRetries = 5

var aesKeyLen = 32

// physicalname (vault key) not needed when  using insure env vars.
func (v *VcdPlatform) PopulateOrgLoginCredsFromEnv(ctx context.Context) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "PopulateOrgLoginCredsFromEnv")

	creds := VcdConfigParams{
		User:      os.Getenv("VCD_USER"),
		Password:  os.Getenv("VCD_PASSWORD"),
		Org:       os.Getenv("VCD_ORG"),
		VcdApiUrl: os.Getenv("VCD_URL"),
		VDC:       os.Getenv("VDC_NAME"),
		Insecure:  true,
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
	if creds.VcdApiUrl == "" {
		return fmt.Errorf("VcdApiUrl not defined")
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

// sanitizeAesKey takes the cloudlet key and makes it suitable
// for AES encryption by forcing it to a standard length
func getAesKeyFromCloudletKey(cloudletKey *edgeproto.CloudletKey) string {
	keyString := cloudletKey.Organization + "-" + cloudletKey.Name

	keylen := len(keyString)
	if keylen > aesKeyLen {
		keyString = keyString[:aesKeyLen]
		keylen = aesKeyLen
	}
	padCount := aesKeyLen - keylen
	keystringNew := keyString + strings.Repeat("*", padCount)
	return keystringNew
}

// EncryptToken encrypts a token via AES using the cloudlet name. Because we store the token in the
// cloudlet via notify, it is visible in a lot of logs.  Perform simple encryption of the token using
// the cloudlet key to at least provide some level of protection if the logs are seen.
func EncryptToken(ctx context.Context, token string, cloudletKey *edgeproto.CloudletKey) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "EncryptToken")

	keyString := getAesKeyFromCloudletKey(cloudletKey)
	c, err := aes.NewCipher([]byte(keyString))
	if err != nil {
		return "", fmt.Errorf("Failed to create cipher block to encrypt token: %v", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", fmt.Errorf("Failed to create cipher GCM to encrypt token: %v", err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(token), nil)
	b64 := base64.StdEncoding.EncodeToString(ciphertext)
	return b64, nil
}

func DecryptToken(ctx context.Context, encTokenB64 string, cloudletKey *edgeproto.CloudletKey) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "DecryptToken")

	keyString := getAesKeyFromCloudletKey(cloudletKey)
	encToken, err := base64.StdEncoding.DecodeString(encTokenB64)

	//Create a new Cipher Block from the key
	c, err := aes.NewCipher([]byte(keyString))
	if err != nil {
		return "", fmt.Errorf("Failed to create cipher to decrypt token: %v", err)
	}

	//Create a new GCM
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", fmt.Errorf("Failed to create cipher GCM to decrypt token: %v", err)
	}

	//Get the nonce size
	nonceSize := gcm.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := encToken[:nonceSize], encToken[nonceSize:]

	//Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("Failed to decrypt and authorize token: %v", err)
	}
	return string(plaintext), nil
}

func (v *VcdPlatform) PopulateOrgLoginCredsFromVcdVars(ctx context.Context) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "PopulateOrgLoginCredsFromVault")
	creds := VcdConfigParams{
		User:                  v.GetVCDUser(),
		Password:              v.GetVCDPassword(),
		Org:                   v.GetVCDORG(),
		VcdApiUrl:             v.GetVcdUrl(),
		VDC:                   v.GetVDCName(),
		OauthSgwUrl:           v.GetVcdOauthSgwUrl(),
		OauthAgwUrl:           v.GetVcdOauthAgwUrl(),
		OauthClientId:         v.GetVcdOauthClientId(),
		OauthClientSecret:     v.GetVcdOauthClientSecret(),
		ClientTlsCert:         v.GetVcdClientTlsCert(),
		ClientTlsKey:          v.GetVcdClientTlsKey(),
		ClientRefreshInterval: v.GetVcdClientRefreshInterval(ctx),
		Insecure:              v.GetVcdInsecure(),
	}
	if creds.OauthSgwUrl != "" {
		if creds.OauthAgwUrl == "" || creds.OauthClientId == "" || creds.OauthClientSecret == "" {
			return fmt.Errorf("OauthAgwUrl is set but other OAUTH related parameter(s) are empty")
		}
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
	if creds.VcdApiUrl == "" {
		return fmt.Errorf("VCD Href not defined")
	}
	if creds.VDC == "" {
		return fmt.Errorf("missing VDC name")
	}
	v.Creds = &creds

	log.SpanLog(ctx, log.DebugLevelInfra, "client login creds", "user", creds.User, "Org", creds.Org, "Vdc", creds.VDC, "URI", "creds.Href")

	return nil
}

func (v *VcdPlatform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, trustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB", "rootLBName", rootLBName, "secGrpName", secGrpName)
	iptblStart := time.Now()
	egressRestricted := false

	// Check if we have any trust policy, and use it if so
	tp, err := v.GetCloudletTrustPolicy(ctx)
	if tp == nil || err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB no TrustPolicy")
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB have TrustPolicy", "trustPolicy", tp)
		trustPolicy = tp
	}
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	// configure iptables based security
	sshCidrsAllowed := []string{infracommon.RemoteCidrAll}

	var rules []edgeproto.SecurityRule
	if tp != nil && tp.Key.Name != "" {
		egressRestricted = true
		rules = trustPolicy.OutboundSecurityRules
	}
	commonSharedAccess := rootLBName == v.vmProperties.SharedRootLBName
	err = v.vmProperties.SetupIptablesRulesForRootLB(ctx, client, sshCidrsAllowed, egressRestricted, secGrpName, rules, commonSharedAccess)
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

func (v *VcdPlatform) RefreshOauthTokenPeriodic(ctx context.Context, creds *VcdConfigParams) {
	interval := time.Second * time.Duration(v.GetVcdClientRefreshInterval(ctx))
	for {
		select {
		case <-time.After(interval):
		}
		span := log.StartSpan(log.DebugLevelInfra, "refresh oauth oauth token")
		ctx := log.ContextWithSpan(context.Background(), span)
		var err error
		success := false
		for retryNum := 0; retryNum <= maxOauthRefreshRetries; retryNum++ {
			log.SpanLog(ctx, log.DebugLevelInfra, "Attempting to update oauth token", "retryNum", retryNum)
			err = v.UpdateOauthToken(ctx, creds)
			if err == nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "refresh oauth ok", "retryNum", retryNum)
				success = true
				break
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "refresh oauth failed, sleep 5 seconds for retry", "err", err)
				time.Sleep(time.Second * 5)
			}
		}
		if !success {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to refresh oauth token after retries, exiting", "err", err)
			log.FatalLog("failed to refresh oauth token after retries", "err", err)
		}
		span.Finish()
	}
}

func (v *VcdPlatform) WaitForOauthTokenViaNotify(ctx context.Context, ckey *edgeproto.CloudletKey) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WaitForOauthTokenViaNotify", "max time", maxOauthTokenFromNotify)

	done := make(chan bool, 1)

	checkDone := func(ctx context.Context) {
		var cloudletInternal edgeproto.CloudletInternal
		if !v.caches.CloudletInternalCache.Get(ckey, &cloudletInternal) {
			return
		}
		token, ok := cloudletInternal.Props[vmlayer.CloudletAccessToken]
		if ok && token != "" {
			log.SpanLog(ctx, log.DebugLevelInfra, "found token in cloudlet cache")
			v.vmProperties.CloudletAccessToken = token
			select {
			case done <- true:
			default:
			}
		}
	}
	cancel := v.caches.CloudletInternalCache.WatchKey(ckey, checkDone)
	// check in case it got updated before the watch
	checkDone(ctx)
	var err error
	select {
	case <-done:
		// we're done
		err = nil
	case <-time.After(maxOauthTokenFromNotify):
		// timed out
		err = fmt.Errorf("Timed out waiting for auth token from notify")
	}
	cancel()
	return err
}

func (v *VcdPlatform) UpdateOauthToken(ctx context.Context, creds *VcdConfigParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateOauthToken", "user", creds.User, "OauthSgwUrl", creds.OauthSgwUrl)

	oauthFailReason := ""
	oauthTokenReceived := ""
	encToken := ""

	u, err := url.ParseRequestURI(creds.OauthAgwUrl)
	if err != nil {
		return fmt.Errorf("Unable to parse request to org %s at %s err: %s", creds.Org, creds.VcdApiUrl, err)
	}

	cloudletClient := govcd.NewVCDClient(*u, creds.Insecure,
		govcd.WithOauthUrl(creds.OauthSgwUrl),
		govcd.WithClientTlsCerts(creds.ClientTlsCert, creds.ClientTlsKey),
		govcd.WithOauthCreds(creds.OauthClientId, creds.OauthClientSecret))

	resp, err := cloudletClient.GetOauthResponse(creds.User, creds.Password, creds.Org)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error oauth response", "org", creds.Org, "err", err)
		oauthFailReason = fmt.Sprintf("O-Auth Error received - %v", err)
	} else if resp.StatusCode != http.StatusOK {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed oauth response", "org", creds.Org, "StatusCode", resp.StatusCode)
		oauthFailReason = fmt.Sprintf("O-Auth Failure Status received - %d", resp.StatusCode)
	}
	if oauthFailReason == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "Got successful oauth response, now verify VCD login")

		// now wait for the token to actually start working, which may not be immediate
		start := time.Now()
		// first wait for the rootlb to exist so we can get a client
		for {
			// start with a sleep to give the oauth token time to propagate
			time.Sleep(3 * time.Second)
			log.SpanLog(ctx, log.DebugLevelInfra, "Trying Oauth token", "url", creds.OauthAgwUrl)
			elapsed := time.Since(start)
			_, err := cloudletClient.GetAuthResponse(creds.User, creds.Password, creds.Org)
			if err == nil {
				break
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to get vcd token with oauth token", "err", err)
			if elapsed > maxOauthTokenReady {
				return fmt.Errorf("timed out waiting for oauth token to work -- %v", err)
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "sleeping 3 seconds before retry")
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Got successful VCD auth response")
		oauthTokenReceived = cloudletClient.Client.OauthAccessToken
	}
	var cloudletInternal edgeproto.CloudletInternal
	// if we did not get an oauth token due to some error, leave encToken empty so it can be sent to shepherd
	// so that shepherd can stop using its old token, if any
	if oauthTokenReceived != "" {
		encToken, err = EncryptToken(ctx, oauthTokenReceived, (v.vmProperties.CommonPf.PlatformConfig.CloudletKey))
		if err != nil {
			return fmt.Errorf("encrypt token error - %v", err)
		}
	}
	// internal Cache can be nil when running on the controller
	if v.caches.CloudletInternalCache != nil {
		if !v.caches.CloudletInternalCache.Get(v.vmProperties.CommonPf.PlatformConfig.CloudletKey, &cloudletInternal) {
			return fmt.Errorf("cannot get cloudlet internal from cache")
		}
		cloudletInternal.Props[vmlayer.CloudletAccessToken] = encToken
		log.SpanLog(ctx, log.DebugLevelInfra, "Saving encrypted Oauth token to cache")
		v.caches.CloudletInternalCache.Update(ctx, &cloudletInternal, 0)
	}
	if oauthFailReason != "" {
		return fmt.Errorf(oauthFailReason)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Saving encrypted Oauth token to vmProperties")
	v.vmProperties.CloudletAccessToken = encToken
	return nil
}

// GetClient gets a new client object.  Copies are made of the global client object, which instantiates a new
// http client but shares the access token
func (v *VcdPlatform) GetClient(ctx context.Context, creds *VcdConfigParams) (client *govcd.VCDClient, err error) {

	apiUrl := creds.VcdApiUrl
	if creds.OauthAgwUrl != "" {
		apiUrl = creds.OauthAgwUrl
	}
	u, err := url.ParseRequestURI(apiUrl)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse request to org %s at %s err: %s", creds.Org, creds.VcdApiUrl, err)
	}
	if v.TestMode {
		err := v.PopulateOrgLoginCredsFromEnv(ctx)
		if err != nil {
			return nil, err
		}
		if creds == nil {
			// usually indicates we called GetClient before InitProvider
			return nil, fmt.Errorf("nil creds passed to GetClient")
		}
		u, err := url.ParseRequestURI(creds.VcdApiUrl)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse request to org %s at %s err: %s", creds.Org, creds.VcdApiUrl, err)
		}
		vcdClient := govcd.NewVCDClient(*u, creds.Insecure)
		if vcdClient.Client.VCDToken != "" {
			_ = vcdClient.SetToken(creds.Org, govcd.AuthorizationHeader, creds.TestToken)
		} else {
			_, err := vcdClient.GetAuthResponse(creds.User, creds.Password, creds.Org)
			if err != nil {
				return nil, fmt.Errorf("Unable to login to org %s at %s err: %s", creds.Org, creds.VcdApiUrl, err)
			}
		}
		return vcdClient, nil
	}
	if creds == nil {
		// usually indicates we called GetClient before InitProvider
		return nil, fmt.Errorf("nil creds passed to GetClient")
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "GetClient", "user", creds.User, "OauthSgwUrl", creds.OauthSgwUrl)
	vcdClient := govcd.NewVCDClient(*u, creds.Insecure,
		govcd.WithOauthUrl(creds.OauthSgwUrl),
		govcd.WithClientTlsCerts(creds.ClientTlsCert, creds.ClientTlsKey),
		govcd.WithOauthCreds(creds.OauthClientId, creds.OauthClientSecret))

	if creds.OauthSgwUrl != "" && v.vmProperties.CloudletAccessToken == "" {
		return nil, fmt.Errorf("Oauth GW specified but no cloudlet Token found")
	}
	if v.vmProperties.CloudletAccessToken != "" {
		decToken, err := DecryptToken(ctx, v.vmProperties.CloudletAccessToken, v.vmProperties.CommonPf.PlatformConfig.CloudletKey)
		if err != nil {
			return nil, err
		}
		vcdClient.Client.OauthAccessToken = decToken
	}

	// always refresh the vcd session token
	_, err = vcdClient.GetAuthResponse(creds.User, creds.Password, creds.Org)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Unable to login to org", "org", creds.Org, "err", err)
		return nil, fmt.Errorf("failed auth response %s at %s err: %s", creds.Org, creds.OauthSgwUrl, err)
	}

	return vcdClient, nil
}

// Common code to configure security rules for a TrustPolicy or TrustPolicyException
func (v *VcdPlatform) configureVCDSecurityRulesCommon(ctx context.Context, egressRestricted bool, secGrpName string, sshCidrsAllowed []string, rules []edgeproto.SecurityRule, rootlbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {

	errMap := make(map[string]error)
	updateCallback(edgeproto.UpdateTask, "Configuring Cloudlet Security Rules")
	log.SpanLog(ctx, log.DebugLevelInfra, "configureVCDSecurityRulesCommon", "action", action, "egressRestricted", egressRestricted, "Cloudlet secgrp name", secGrpName)

	if action == vmlayer.ActionCreate || action == vmlayer.ActionUpdate {
		for clientName, sshClient := range rootlbClients {
			var err error
			if sshClient == nil {
				// in error conditions GetRootLbClients will populate with a nil client
				err = fmt.Errorf("nil ssh client for rootlb: %s", clientName)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "configure rules for LB", "clientName", clientName)
				err = v.vmProperties.SetupIptablesRulesForRootLB(ctx, sshClient, sshCidrsAllowed, egressRestricted, secGrpName, rules, clientName == v.vmProperties.PlatformSecgrpName)
			}
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "configureVCDSecurityRulesCommon failed", "clientName", clientName, "sshClient", sshClient, "error", err)
				errMap[clientName] = err
			}
		}

		if len(errMap) != 0 {
			log.SpanLog(ctx, log.DebugLevelInfra, "configureVCDSecurityRulesCommon encountered errors:")
			for n, e := range errMap {
				log.SpanLog(ctx, log.DebugLevelInfra, "configureVCDSecurityRulesCommon error", "server", n, "error", e)
			}
			failedLbs := []string{}
			for k := range errMap {
				failedLbs = append(failedLbs, k)
			}
			lbList := strings.Join(failedLbs, ",")
			ckey := v.vmProperties.CommonPf.PlatformConfig.CloudletKey
			// TODO: consider making this an Alert rather than an Event
			v.vmProperties.CommonPf.PlatformConfig.NodeMgr.Event(ctx, "Failed to configure iptables security rules", ckey.Organization, ckey.GetTags(), nil, "rootLBs", lbList)
			return fmt.Errorf("Failure in configureVCDSecurityRulesCommon for rootLBs: %s", lbList)
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "configureVCDSecurityRulesCommon action.delete")
		for clientName, sshClient := range rootlbClients {
			var err error
			if sshClient == nil {
				// in error conditions GetRootLbClients will populate with a nil client
				err = fmt.Errorf("nil ssh client for rootlb: %s", clientName)
				continue
			}
			err = infracommon.RemoveRulesForLabel(ctx, sshClient, secGrpName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "configureVCDSecurityRulesCommon RemoveRulesForLabel fail", "error", err)
			}
		}
	}

	return nil
}

func (v *VcdPlatform) ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, rootlbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {

	var rules []edgeproto.SecurityRule
	if TrustPolicy != nil {
		rules = TrustPolicy.OutboundSecurityRules
	}
	secGrpName := infracommon.TrustPolicySecGrpNameLabel
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules", "egressRestricted", egressRestricted, "TrustPolicy", TrustPolicy, "action", action, "secGrpName", secGrpName)
	sshCidrsAllowed := []string{infracommon.RemoteCidrAll}
	return v.configureVCDSecurityRulesCommon(ctx, egressRestricted, secGrpName, sshCidrsAllowed, rules, rootlbClients, action, updateCallback)
}

func (v *VcdPlatform) getTrustPolicyExceptionSecurityGroupName(tpeKey *edgeproto.TrustPolicyExceptionKey) string {
	grpName := v.NameSanitize(tpeKey.Name + "-" + tpeKey.AppKey.Name + "-" + tpeKey.AppKey.Organization + "-" + tpeKey.AppKey.Version + "-" + tpeKey.CloudletPoolKey.Name + "-" + tpeKey.CloudletPoolKey.Organization)
	return grpName
}

func (v *VcdPlatform) ConfigureTrustPolicyExceptionSecurityRules(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, rootLbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	secGrpName := v.getTrustPolicyExceptionSecurityGroupName(&TrustPolicyException.Key)
	egressRestricted := true
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureTrustPolicyExceptionSecurityRules", "egressRestricted", egressRestricted, "TrustPolicyException", TrustPolicyException, "action", action, "secGrpName", secGrpName)
	sshCidrsAllowed := []string{}
	return v.configureVCDSecurityRulesCommon(ctx, egressRestricted, secGrpName, sshCidrsAllowed, TrustPolicyException.OutboundSecurityRules, rootLbClients, action, updateCallback)
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
			// update the org in context
			org, err := vcdClient.GetOrgByName(v.Creds.Org)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetOrgByName failed", "org", v.Creds.Org, "err", err)
				return ctx, vmlayer.OperationInitFailed, err
			}
			ctx = context.WithValue(ctx, VCDOrgCtxKey, org)
			// update vdc in context
			vdc, err := org.GetVDCByName(v.Creds.VDC, false)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetVdcByName failed", "org", v.Creds.Org, "err", err)
				return ctx, vmlayer.OperationInitFailed, err
			}
			ctx = context.WithValue(ctx, VCDVdcCtxKey, vdc)
			return ctx, vmlayer.OperationNewlyInitialized, nil
		}
	} else {
		// because we re-use copies of the context, we do not try to disconnect the client.
		// Disconnect generally does not work in VCD anyway
		return ctx, vmlayer.OperationNewlyInitialized, nil
	}
}

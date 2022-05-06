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

package infracommon

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/access"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/proxy"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/edgeproto"

	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type WhiteListParams struct {
	SecGrpName  string
	ServerName  string
	Label       string
	AllowedCIDR string
	DestIP      string
	Ports       []dme.AppPort
}

type WhiteListFunc func(ctx context.Context, client ssh.Client, wlParams *WhiteListParams) error

type ProxyDnsSecOpts struct {
	AddProxy              bool
	AddDnsAndPatchKubeSvc bool
	AddSecurityRules      bool
	ProxyNamePrefix       string
}

const RemoteCidrAll = "0.0.0.0/0"
const RemoteCidrNone = "0.0.0.0/32"

const DestIPUnspecified = ""

func GetAllowedClientCIDR() string {
	return RemoteCidrAll
}

func GetAppWhitelistRulesLabel(app *edgeproto.App) string {
	return "appaccess-" + k8smgmt.NormalizeName(app.Key.Name)
}

// GetServerSecurityGroupName gets the secgrp name based on the server name
func GetServerSecurityGroupName(serverName string) string {
	return serverName + "-sg"
}

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func (c *CommonPlatform) AddProxySecurityRulesAndPatchDNS(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, getDnsSvcAction GetDnsSvcActionFunc, whiteListAdd WhiteListFunc, wlParams *WhiteListParams, listenIP, backendIP string, ops ProxyDnsSecOpts, proxyops ...proxy.Op) error {
	secchan := make(chan string)
	dnschan := make(chan string)
	proxychan := make(chan string)

	log.SpanLog(ctx, log.DebugLevelInfra, "AddProxySecurityRulesAndPatchDNS", "appname", kubeNames.AppName, "listenIP", listenIP, "backendIP", backendIP, "wlParams", wlParams, "ops", ops)
	if len(wlParams.Ports) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "no ports specified, no DNS, LB or Security rules needed", "appname", kubeNames.AppName)
		return nil
	}
	configs := append(app.Configs, appInst.Configs...)
	aac, err := access.GetAppAccessConfig(ctx, configs, app.TemplateDelimiter)
	if err != nil {
		return err
	}
	go func() {
		if ops.AddProxy {
			// TODO update certs once AppAccessConfig functionality is added back
			/*if aac.LbTlsCertCommonName != "" {
			        ... get cert here
			}*/
			containerName := ops.ProxyNamePrefix + dockermgmt.GetContainerName(&app.Key)
			proxyerr := proxy.CreateNginxProxy(ctx, client, containerName, listenIP, backendIP, appInst, app.SkipHcPorts, proxyops...)
			if proxyerr == nil {
				proxychan <- ""
			} else {
				proxychan <- proxyerr.Error()
			}
		} else {
			proxychan <- ""
		}
	}()
	go func() {
		if ops.AddSecurityRules {
			wlParams.AllowedCIDR = GetAllowedClientCIDR()
			err := whiteListAdd(ctx, client, wlParams)
			if err == nil {
				secchan <- ""
			} else {
				secchan <- err.Error()
			}
		} else {
			secchan <- ""
		}
	}()
	go func() {
		if ops.AddDnsAndPatchKubeSvc {
			err := c.CreateAppDNSAndPatchKubeSvc(ctx, client, kubeNames, aac.DnsOverride, getDnsSvcAction)
			if err == nil {
				dnschan <- ""
			} else {
				dnschan <- err.Error()
			}
		} else {
			dnschan <- ""
		}
	}()
	proxyerr := <-proxychan
	secerr := <-secchan
	dnserr := <-dnschan

	if proxyerr != "" || secerr != "" || dnserr != "" {
		return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error -- proxyerr: %v secerr: %v dnserr: %v", proxyerr, secerr, dnserr)
	}
	return nil
}

func (c *CommonPlatform) DeleteProxySecurityGroupRules(ctx context.Context, client ssh.Client, proxyName string, whiteListDel WhiteListFunc, wlParams *WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteProxySecurityGroupRules", "proxyName", proxyName, "wlParams", wlParams)

	err := proxy.DeleteNginxProxy(ctx, client, proxyName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete proxy", "proxyName", proxyName, "error", err)
	}
	return whiteListDel(ctx, client, wlParams)
}

// GetUniqueLoopbackIp returns an IP on the loopback interface, which is anything in the
// 127.0.0.0/8 subnet.   The purpose is to have a unique loopback IP which can be used for the
// envoy metrics port.  The IP returned is derived from the highest number app port as follows
// First octet: 127
// Second octet:  1 if highest port is TCP, 2 if highest port is UDP
// Third and fourth octets: highest port number
func GetUniqueLoopbackIp(ctx context.Context, ports []dme.AppPort) string {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetUniqueLoopbackIp", "ports", ports)

	var maxUdp int32 = 0
	var maxTcp int32 = 0
	var maxPort int32 = 0
	for _, p := range ports {
		endPort := p.EndPort
		if endPort == 0 {
			endPort = p.PublicPort
		}
		if p.Proto == dme.LProto_L_PROTO_TCP {
			if endPort > maxTcp {
				maxTcp = endPort
			}
		} else {
			if endPort > maxUdp {
				maxUdp = endPort
			}
		}
	}
	var oct2 string
	if maxTcp >= maxUdp {
		oct2 = "1" // tcp
		maxPort = maxTcp
	} else {
		oct2 = "2" // udp
		maxPort = maxUdp
	}
	oct3 := maxPort / 256
	oct4 := maxPort % 256
	result := fmt.Sprintf("127.%s.%d.%d", oct2, oct3, oct4)
	log.SpanLog(ctx, log.DebugLevelInfra, "GetUniqueLoopbackIp", "maxUdp", maxUdp, "maxTcp", maxTcp, "result", result)
	return result
}

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

package crmutil

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/kballard/go-shellquote"
	"github.com/xtaci/smux"
)

func (cd *CRMHandler) ProcessExecReq(ctx context.Context, pf platform.Platform, req *edgeproto.ExecRequest, sendReply func(msg *edgeproto.ExecRequest)) (reterr error) {
	var err error
	log.SpanLog(ctx, log.DebugLevelApi, "ProcessExecReq", "req", req)

	run := &RunExec{
		req: req,
	}

	appInst := edgeproto.AppInst{}
	app := edgeproto.App{}
	if req.Cmd == nil || req.Cmd.CloudletMgmtNode == nil {
		found := cd.AppInstCache.Get(&req.AppInstKey, &appInst)
		if !found {
			return fmt.Errorf("app inst %s not found",
				req.AppInstKey.GetKeyString())
		}
		found = cd.AppCache.Get(&appInst.AppKey, &app)
		if !found {
			return fmt.Errorf("app %s not found",
				appInst.AppKey.GetKeyString())
		}
	}

	var execReqType cloudcommon.ExecReqType
	var initURL *url.URL
	if req.Console != nil {
		req.Console.Url, err = pf.GetConsoleUrl(ctx, &app, &appInst)
		if err != nil {
			return err
		}
		urlObj, err := url.Parse(req.Console.Url)
		if err != nil {
			return fmt.Errorf("unable to parse console url, %s, %v", req.Console.Url, err)
		}
		execReqType = cloudcommon.ExecReqConsole
		initURL = urlObj
	} else if req.Cmd != nil && req.Cmd.CloudletMgmtNode != nil {
		clusterInsts := []edgeproto.ClusterInst{}
		cd.ClusterInstCache.Mux.Lock()
		for _, v := range cd.ClusterInstCache.Objs {
			clusterInsts = append(clusterInsts, *v.Obj)
		}
		cd.ClusterInstCache.Mux.Unlock()
		vmAppInsts := []edgeproto.AppInst{}
		cd.AppInstCache.Mux.Lock()
		for _, v := range cd.AppInstCache.Objs {
			appObj := edgeproto.App{}
			found := cd.AppCache.Get(&v.Obj.AppKey, &appObj)
			if found && appObj.Deployment == cloudcommon.DeploymentTypeVM {
				vmAppInsts = append(vmAppInsts, *v.Obj)
			}
		}
		cd.AppInstCache.Mux.Unlock()
		nodes, err := pf.ListCloudletMgmtNodes(ctx, clusterInsts, vmAppInsts)
		if err != nil {
			return fmt.Errorf("unable to get list of cloudlet mgmt nodes, %v", err)
		}
		if len(nodes) == 0 {
			return fmt.Errorf("no nodes found")
		}
		accessNode := req.Cmd.CloudletMgmtNode
		matchedNodes := []edgeproto.CloudletMgmtNode{}
		for _, node := range nodes {
			// filter by specified node/type.
			// blank means match any.
			if accessNode.Type != "" && accessNode.Type != node.Type {
				continue
			}
			if accessNode.Name != "" && accessNode.Name != node.Name {
				continue
			}
			matchedNodes = append(matchedNodes, node)
		}
		if len(matchedNodes) == 0 {
			return fmt.Errorf("unable to find specified cloudlet mgmt node, list of valid nodes: %v", nodes)
		} else if len(matchedNodes) > 1 {
			return fmt.Errorf("too many nodes matched, please specify type and name from: %v", matchedNodes)
		}
		accessNode = &matchedNodes[0]

		run.contcmd = "bash"
		if req.Cmd.Command != "" {
			run.contcmd = req.Cmd.Command
		}
		run.client, err = pf.GetNodePlatformClient(ctx, accessNode)
		if err != nil {
			return err
		}
		execReqType = cloudcommon.ExecReqShell
	} else {
		execReqType = cloudcommon.ExecReqShell
		clusterInst := edgeproto.ClusterInst{}
		found := cd.ClusterInstCache.Get(appInst.ClusterInstKey(), &clusterInst)
		if !found {
			return fmt.Errorf("cluster inst %s not found",
				appInst.ClusterInstKey().GetKeyString())
		}

		run.contcmd, err = pf.GetContainerCommand(ctx, &clusterInst, &app, &appInst, req)
		if err != nil {
			return err
		}

		clientType := cloudcommon.GetAppClientType(&app)
		run.client, err = pf.GetClusterPlatformClient(ctx, &clusterInst, clientType)
		if err != nil {
			return err
		}
	}

	// Connect to EdgeTurn server
	if req.EdgeTurnAddr == "" {
		return fmt.Errorf("no edgeturn server address specified")
	}
	if req.EdgeTurnProxyAddr == "" {
		return fmt.Errorf("no edgeturn proxy address specified")
	}

	tlsConfig, err := cd.NodeMgr.InternalPki.GetClientTlsConfig(ctx,
		cd.NodeMgr.CommonNamePrefix(),
		node.CertIssuerRegionalCloudlet,
		[]node.MatchCA{node.SameRegionalMatchCA()})
	if err != nil {
		return err
	}
	turnConn, err := tls.Dial("tcp", req.EdgeTurnAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to edgeturn server: %v", err)
	}
	defer turnConn.Close()

	// Send ExecReqInfo to EdgeTurn server
	execReqInfo := cloudcommon.ExecReqInfo{
		Type:    execReqType,
		InitURL: initURL,
	}
	out, err := json.Marshal(&execReqInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal execReqInfo %v, %v", execReqInfo, err)
	}
	turnConn.Write(out)
	log.SpanLog(ctx, log.DebugLevelApi, "sent execreq info", "info", string(out))

	// Fetch session info from EdgeTurn server
	var sessInfo cloudcommon.SessionInfo
	d := json.NewDecoder(turnConn)
	err = d.Decode(&sessInfo)
	if err != nil {
		return fmt.Errorf("failed to decode session info: %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "received session info from edgeturn server", "info", sessInfo)

	replySent := false
	// if ExecRequest reply is already sent, we can't send any error back to the
	// client via the ExecRequest. Instead we'll need to write it to the
	// turn connection.
	defer func() {
		if reterr != nil && replySent {
			turnConn.Write([]byte(reterr.Error()))
		}
	}()
	if req.Console != nil {
		urlObj, err := url.Parse(req.Console.Url)
		if err != nil {
			return fmt.Errorf("failed to parse console url %s, %v", req.Console.Url, err)
		}
		isTLS := false
		if urlObj.Scheme == "http" {
			isTLS = false
		} else if urlObj.Scheme == "https" {
			isTLS = true
		} else {
			return fmt.Errorf("unsupported scheme %s", urlObj.Scheme)
		}
		sess, err := smux.Server(turnConn, nil)
		if err != nil {
			return fmt.Errorf("failed to setup smux server, %v", err)
		}
		// Verify if connection to url is okay
		var server net.Conn
		if isTLS {
			server, err = tls.Dial("tcp", urlObj.Host, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err != nil {
				return fmt.Errorf("failed to get console, %v", err)
			}
		} else {
			server, err = net.Dial("tcp", urlObj.Host)
			if err != nil {
				return fmt.Errorf("failed to get console, %v", err)
			}
		}
		server.Close()
		defer sess.Close()
		// Notify controller that connection is setup
		proxyAddr := "https://" + req.EdgeTurnProxyAddr + "/edgeconsole?edgetoken=" + sessInfo.Token
		req.AccessUrl = proxyAddr
		sendReply(req)
		replySent = true
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				if err.Error() != io.ErrClosedPipe.Error() {
					return fmt.Errorf("failed to setup smux acceptstream, %v", err)
				}
				return nil
			}
			if isTLS {
				server, err = tls.Dial("tcp", urlObj.Host, &tls.Config{
					InsecureSkipVerify: true,
				})
				if err != nil {
					return fmt.Errorf("failed to get console, %v", err)
				}
			} else {
				server, err = net.Dial("tcp", urlObj.Host)
				if err != nil {
					return fmt.Errorf("failed to get console, %v", err)
				}
			}
			go func(server net.Conn, stream *smux.Stream) {
				buf := make([]byte, 1500)
				for {
					n, err := stream.Read(buf)
					if err != nil {
						break
					}
					server.Write(buf[:n])
				}
				stream.Close()
				server.Close()
			}(server, stream)
			go func(server net.Conn, stream *smux.Stream) {
				buf := make([]byte, 1500)
				for {
					n, err := server.Read(buf)
					if err != nil {
						break
					}
					stream.Write(buf[:n])
				}
				stream.Close()
				server.Close()
			}(server, stream)
		}
	} else {
		proxyAddr := "wss://" + req.EdgeTurnProxyAddr + "/edgeshell?edgetoken=" + sessInfo.Token
		req.AccessUrl = proxyAddr
		sendReply(req)
		replySent = true
		err = run.proxyRawConn(turnConn)
		if err != nil {
			return err
		}
	}

	return nil
}

type RunExec struct {
	req     *edgeproto.ExecRequest
	client  ssh.Client
	contcmd string
}

func (s *RunExec) proxyRawConn(turnConn net.Conn) error {
	args, err := shellquote.Split(strings.TrimSpace(s.contcmd))
	if err != nil {
		return fmt.Errorf("bad command %s: %s", s.contcmd, err)
	}
	prd, pwr := io.Pipe()
	go io.Copy(pwr, turnConn)
	err = pc.RunSafeShell(s.client, prd, turnConn, turnConn, args[0], args[1:])
	if err != nil {
		log.DebugLog(log.DebugLevelApi,
			"failed to exec",
			"cmd", s.contcmd, "args", args, "err", err)
	}
	return err
}

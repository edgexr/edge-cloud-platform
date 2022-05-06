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

package operalpha

import (
	"context"
	"net"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	locclient "github.com/edgexr/edge-cloud-infra/operator-api-gw/operalpha/operalpha-loc/locclient"
	qosclient "github.com/edgexr/edge-cloud-infra/operator-api-gw/operalpha/operalpha-qos/qosclient"
	sessionsclient "github.com/edgexr/edge-cloud-infra/operator-api-gw/operalpha/operalpha-sessions/sessionsclient"
	"github.com/edgexr/edge-cloud-infra/version"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	operator "github.com/edgexr/edge-cloud/d-match-engine/operator"
	simulatedloc "github.com/edgexr/edge-cloud/d-match-engine/operator/defaultoperator/simulated-location"
	simulatedqos "github.com/edgexr/edge-cloud/d-match-engine/operator/defaultoperator/simulated-qos"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
)

var QosClientCert = "qosclient.crt"
var QosClientKey = "qosclient.key"
var QoServerCert = "qosserver.crt"

var qosSessionsApiKey string

//OperatorApiGw respresent an Operator API Gateway
type OperatorApiGw struct {
	Servers     *operator.OperatorApiGwServers
	vaultConfig *vault.Config
}

func (OperatorApiGw) GetOperatorName() string {
	return "OPERALPHA"
}

// Init is called once during startup.
func (o *OperatorApiGw) Init(operatorName string, servers *operator.OperatorApiGwServers) error {
	log.DebugLog(log.DebugLevelDmereq, "init for operalpha operator", "servers", servers)
	o.Servers = servers
	vaultConfig, err := vault.BestConfig(o.Servers.VaultAddr)
	o.Servers = servers
	if err != nil {
		return err
	}
	o.vaultConfig = vaultConfig

	if o.Servers.QosPosUrl != "" {
		err := qosclient.GetQosCertsFromVault(vaultConfig)
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *OperatorApiGw) VerifyLocation(mreq *dme.VerifyLocationRequest, mreply *dme.VerifyLocationReply) error {

	log.DebugLog(log.DebugLevelDmereq, "OPERALPHA VerifyLocation", "request", mreq)

	if o.Servers.LocVerUrl == "" {
		// because this is so often used for demos, it is better to fail in a clear way
		// than to give a defaultoperator/fake result
		return grpc.Errorf(codes.InvalidArgument, "DME has no location verification server")
	}
	if o.Servers.TokSrvUrl == "" {
		return grpc.Errorf(codes.InvalidArgument, "DME has no token server")
	}
	if mreq.VerifyLocToken == "" {
		return grpc.Errorf(codes.InvalidArgument, "no VerifyLocToken in request")
	}
	// this is checked in the DME, but since we dereference it we will check it in this code as well
	if mreq.GpsLocation == nil {
		return grpc.Errorf(codes.InvalidArgument, "no GpsLocation in request")
	}

	result := locclient.CallOPERALPHALocationVerifyAPI(o.Servers.LocVerUrl, mreq.GpsLocation.Latitude, mreq.GpsLocation.Longitude, mreq.VerifyLocToken, o.Servers.TokSrvUrl)
	mreply.GpsLocationStatus = result.MatchEngineLocStatus
	mreply.GpsLocationAccuracyKm = result.DistanceRange
	log.DebugLog(log.DebugLevelDmereq, "OPERALPHA VerifyLocation result", "mreply", mreply)
	return nil
}

func (o *OperatorApiGw) GetLocation(mreq *dme.GetLocationRequest, mreply *dme.GetLocationReply) error {
	log.DebugLog(log.DebugLevelDmereq, "OPERALPHA GetLocation", "request", mreq)
	// We have no real implementation of this
	return simulatedloc.GetSimulatedClientLoc(mreq, mreply)
}

func (o *OperatorApiGw) GetQOSPositionKPI(mreq *dme.QosPositionRequest, getQosSvr dme.MatchEngineApi_GetQosPositionKpiServer) error {
	log.DebugLog(log.DebugLevelDmereq, "OPERALPHA GetQOSPositionKPI", "QosPosUrl", o.Servers.QosPosUrl, "request", mreq)

	if o.Servers.QosPosUrl == "" {
		log.DebugLog(log.DebugLevelDmereq, "No QosPosUrl, getting simulated results")
		return simulatedqos.GetSimulatedQOSPositionKPI(mreq, getQosSvr)
	}
	return qosclient.GetQOSPositionFromApiGW(o.Servers.QosPosUrl, mreq, getQosSvr)
}

func (*OperatorApiGw) GetVersionProperties() map[string]string {
	return version.InfraBuildProps("OPERALPHAOperator")
}

func (o *OperatorApiGw) SetQosSessionsApiKey(key string) {
	qosSessionsApiKey = key
}

func (o *OperatorApiGw) CreatePrioritySession(ctx context.Context, req *dme.QosPrioritySessionCreateRequest) (*dme.QosPrioritySessionReply, error) {
	var reply *dme.QosPrioritySessionReply
	var err error
	log.SpanLog(ctx, log.DebugLevelDmereq, "OPERALPHA CreatePrioritySession", "req", req)
	// Only retrieve this from the vault if we don't already have it.
	if qosSessionsApiKey == "" {
		qosSessionsApiKey, err = sessionsclient.GetApiKeyFromVault(ctx, o.vaultConfig)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelDmereq, "GetApiKeyFromVault failed. QOS priority session creation not supported.", "err", err)
		}
		if qosSessionsApiKey == "" {
			return nil, status.Errorf(codes.Unauthenticated, "missing qosSessionsApiKey")
		}
	}
	// build a request and send it in CallOPERALPHAQosPriorityAPI()
	reqBody := sessionsclient.QosSessionRequest{}
	reqBody.UeAddr = req.IpUserEquipment
	reqBody.AsAddr = req.IpApplicationServer
	reqBody.UePorts = req.PortUserEquipment
	reqBody.AsPorts = req.PortApplicationServer
	reqBody.ProtocolIn = req.ProtocolIn.String()
	reqBody.ProtocolOut = req.ProtocolOut.String()
	reqBody.Qos = req.Profile.String()
	reqBody.Duration = int64(req.SessionDuration)
	if net.ParseIP(req.IpUserEquipment).To4() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Address for IpUserEquipment: %s", req.IpUserEquipment)
	}
	if net.ParseIP(req.IpApplicationServer).To4() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Address for IpApplicationServer: %s", req.IpApplicationServer)
	}
	reply, err = sessionsclient.CallOPERALPHAQosPriorityAPI(ctx, "", http.MethodPost, o.Servers.QosSesAddr, qosSessionsApiKey, reqBody)
	return reply, err
}

func (o *OperatorApiGw) DeletePrioritySession(ctx context.Context, req *dme.QosPrioritySessionDeleteRequest) (*dme.QosPrioritySessionDeleteReply, error) {
	sesInfo := sessionsclient.QosSessionRequest{}
	// Only the Qos (profile name) field is needed for delete.
	sesInfo.Qos = req.Profile.String()
	sessionId := req.SessionId
	log.SpanLog(ctx, log.DebugLevelDmereq, "OPERALPHA DeletePrioritySession", "sessionId", sessionId)
	// Get a generic QosPrioritySessionReply, then build a QosPrioritySessionDeleteReply based on the httpStatus.
	reply, err := sessionsclient.CallOPERALPHAQosPriorityAPI(ctx, sessionId, http.MethodDelete, o.Servers.QosSesAddr, qosSessionsApiKey, sesInfo)
	log.SpanLog(ctx, log.DebugLevelDmereq, "Response from OPERALPHA:", "reply", reply, "err", err)
	if err != nil {
		return nil, err
	}
	deleteReply := new(dme.QosPrioritySessionDeleteReply)
	if reply.HttpStatus == http.StatusNotFound {
		deleteReply.Status = dme.QosPrioritySessionDeleteReply_QDEL_NOT_FOUND
	} else if reply.HttpStatus == http.StatusNoContent {
		deleteReply.Status = dme.QosPrioritySessionDeleteReply_QDEL_DELETED
	} else {
		deleteReply.Status = dme.QosPrioritySessionDeleteReply_QDEL_UNKNOWN
	}
	return deleteReply, err
}

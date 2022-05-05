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

package sessionsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
)

func GetApiKeyFromVault(ctx context.Context, vaultConfig *vault.Config) (string, error) {
	apiKeyPath := "/secret/data/accounts/operalpha/sessionsapi"
	log.SpanLog(ctx, log.DebugLevelDmereq, "GetApiKeyFromVault", "vaultAddr", vaultConfig.Addr, "apiKeyPath", apiKeyPath)
	type ApiKeyData struct {
		Data string
	}
	var apiKeyData ApiKeyData
	err := vault.GetData(vaultConfig, apiKeyPath, 0, &apiKeyData)
	if err != nil {
		return "", fmt.Errorf("unable to fetch QOS API key from vault. err=%v", err)
	}
	apiKey := apiKeyData.Data

	return apiKey, err
}

// From https://staging-portal.hubraum.opsfactory.dev/de/products/617bd0928431ba00019948f4/summary
type QosSessionCommon struct {
	Duration              int64  `json:"duration" yaml:"duration"`
	UeAddr                string `json:"ueAddr" yaml:"ueAddr"`
	AsAddr                string `json:"asAddr" yaml:"asAddr"`
	UePorts               string `json:"uePorts" yaml:"uePorts"`
	AsPorts               string `json:"asPorts" yaml:"asPorts"`
	ProtocolIn            string `json:"protocolIn" yaml:"protocolIn"`
	ProtocolOut           string `json:"protocolOut" yaml:"protocolOut"`
	Qos                   string `json:"qos" yaml:"qos"`
	NotificationUri       string `json:"notificationUri" yaml:"notificationUri"`
	NotificationAuthToken string `json:"notificationAuthToken" yaml:"notificationAuthToken"`
}

type QosSessionRequest struct {
	QosSessionCommon
}

type QosSessionResponse struct {
	QosSessionCommon
	Id        string `json:"id" yaml:"id"`
	StartedAt int64  `json:"startedAt" yaml:"startedAt"`
	ExpiresAt int64  `json:"expiresAt" yaml:"expiresAt"`
}

// Build and send the request to the OPERALPHA API server
func sendRequest(ctx context.Context, method string, reqUrl string, apiKey string, body *bytes.Buffer) (int, string, error) {
	log.SpanLog(ctx, log.DebugLevelDmereq, "Sending to OPERALPHA:", "method", method, "reqUrl:", reqUrl, "body:", body)

	var req *http.Request
	var err error

	// I'm surprised this is necessary, and surprised that it works.
	// See https://github.com/golang/go/issues/32897
	if body == nil {
		req, err = http.NewRequest(method, reqUrl, nil)
	} else {
		req, err = http.NewRequest(method, reqUrl, body)
	}

	if err != nil {
		log.WarnLog("error in http.NewRequest", "err", err)
		return 0, "", err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("accept", "application/json")
	req.Header.Add("Authorization", apiKey)

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		log.WarnLog("Error in REST call to OPERALPHA QOS session priority service", "error", err)
		return 0, "", err
	}
	defer resp.Body.Close()

	log.SpanLog(ctx, log.DebugLevelDmereq, "Received response", "statusCode:", resp.StatusCode)

	respBytes, resperr := ioutil.ReadAll(resp.Body)
	if resperr != nil {
		log.WarnLog("Error reading response body", "resperr", resperr)
		return 0, "", resperr
	}
	respString := string(respBytes)
	log.SpanLog(ctx, log.DebugLevelDmereq, "Converted response to string")

	return resp.StatusCode, respString, nil
}

func buildQosUrl(ctx context.Context, profileName string, qosSesAddr string) (string, error) {
	var priorityType string
	if profileName == "LOW_LATENCY" { // LOW_LATENCY is the only valid latency profile.
		priorityType = "latency"
	} else if strings.HasPrefix(profileName, "THROUGHPUT") {
		priorityType = "throughput"
	} else {
		log.SpanLog(ctx, log.DebugLevelDmereq, "Received invalid value", "profileName", profileName)
		return "", errors.New("Received invalid profileName " + profileName)
	}
	url := fmt.Sprintf("%s/5g-%s/sessions/", qosSesAddr, priorityType) // Inserts either "latency" or "throughput".
	log.SpanLog(ctx, log.DebugLevelDmereq, "buildQosUrl", "url", url)
	return url, nil
}

// CallOPERALPHAQosPriorityAPI REST API client for the OPERALPHA implementation of QOS session priority API.
// If a matching session ((IPs, Ports, Protcol) is found, and the requested profile is also the same,
// that session is kept unchanged.
// If a matching session ((IPs, Ports, Protcol) is found, and the requested profile is different,
// the existing session is deleted, and a new session is created with the requested profile name.
func CallOPERALPHAQosPriorityAPI(ctx context.Context, sesId string, method string, qosSesAddr string, apiKey string, reqBody QosSessionRequest) (*dme.QosPrioritySessionReply, error) {
	reply := new(dme.QosPrioritySessionReply)
	qos := QosProtoToOperalpha(reqBody.Qos)
	log.SpanLog(ctx, log.DebugLevelDmereq, "OPERALPHA CallOPERALPHAQosPriorityAPI", "method", method, "qosSesAddr", qosSesAddr, "qos", qos)
	if qos == "QOS_NO_PRIORITY" {
		return nil, errors.New("Operation not permitted with profileName " + qos)
	}
	reqUrl, err := buildQosUrl(ctx, qos, qosSesAddr)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelDmereq, "Converting QOS Profile name from proto to OPERALPHA", "old", reqBody.Qos, "new", qos)
	reqBody.Qos = qos
	log.SpanLog(ctx, log.DebugLevelDmereq, "OPERALPHA CallOPERALPHAQosPriorityAPI", "reqUrl", reqUrl, "reqBody", reqBody)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	body := bytes.NewBuffer(out)

	// For DELETE, we need to add the session ID to the URL
	if method == http.MethodDelete {
		reqUrl += sesId
	}
	status, respBody, err := sendRequest(ctx, method, reqUrl, apiKey, body)
	if err != nil {
		return nil, err
	}

	var qsiResp QosSessionResponse

	if status == http.StatusConflict {
		log.SpanLog(ctx, log.DebugLevelDmereq, "409 Conflict received")
		// In this case, the session already exists. Look up the session info and see if it needs updated.
		// Example respBody:
		// "Found session 9aa00f58-38f6-4ed9-be8f-d375aad95721 already active until 2021-12-03T21:06:02Z"
		if strings.HasPrefix(respBody, "Found session") {
			words := strings.Split(respBody, " ")
			if len(words) < 3 {
				return nil, fmt.Errorf(fmt.Sprintf("Could not parse response: %s", respBody))
			}
			sessionId := words[2]
			url := fmt.Sprintf("%s/%s", reqUrl, sessionId)
			status, respBody, err = sendRequest(ctx, http.MethodGet, url, apiKey, nil)
			if err != nil {
				return nil, err
			}
			if status == http.StatusOK {
				respBytes := []byte(respBody)
				err = json.Unmarshal(respBytes, &qsiResp)
				if err != nil {
					log.WarnLog("Error unmarshalling response", "respBytes", respBytes, "err", err)
					return nil, err
				}
				if qsiResp.Qos == reqBody.Qos {
					log.SpanLog(ctx, log.DebugLevelDmereq, "Requested QOS session already exists. Keeping it.", "qsiResp.Qos", qsiResp.Qos)
				} else {
					log.SpanLog(ctx, log.DebugLevelDmereq, "Existing QOS profile doesn't match. Deleting session.")
					oldQos := qsiResp.Qos
					url, err := buildQosUrl(ctx, oldQos, qosSesAddr)
					url = fmt.Sprintf("%s%s", url, sessionId)
					if err != nil {
						return nil, err
					}
					status, _, err = sendRequest(ctx, http.MethodDelete, url, apiKey, nil)
					if err != nil {
						return nil, err
					}
					if status == http.StatusNoContent {
						log.SpanLog(ctx, log.DebugLevelDmereq, "Successfully deleted QOS session")
					} else {
						return nil, fmt.Errorf(fmt.Sprintf("Failed to delete existing QOS session: Error code: %d", status))
					}

					// Send new request to create session with desired QOS profile.
					body := bytes.NewBuffer(out)
					status, respBody, err = sendRequest(ctx, method, reqUrl, apiKey, body)
					log.SpanLog(ctx, log.DebugLevelDmereq, "Result of re-send received")

					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	// This value of 'status' can be from the initial call, or from the delete/retry attempt.
	if status == http.StatusCreated || status == http.StatusOK {
		if status == http.StatusCreated {
			log.SpanLog(ctx, log.DebugLevelDmereq, "201 Session Created received")
		} else {
			log.SpanLog(ctx, log.DebugLevelDmereq, "200 OK received")
		}
		respBytes := []byte(respBody)
		err = json.Unmarshal(respBytes, &qsiResp)
		if err != nil {
			log.WarnLog("Error unmarshalling response", "respBytes", respBytes, "err", err)
			return nil, err
		}
		reply.Profile, err = dme.ParseQosSessionProfile(QosOperalphaToProto(qsiResp.Qos))
		if err != nil {
			log.WarnLog("Failed to ParseQosSessionProfile", "qsiResp.Qos", qsiResp.Qos, "QosOperalphaToProto(qsiResp.Qos)", QosOperalphaToProto(qsiResp.Qos), "err", err)
			return nil, err
		}
		reply.SessionDuration = uint32(qsiResp.Duration)
		reply.SessionId = qsiResp.Id
		reply.StartedAt = uint32(qsiResp.StartedAt)
		reply.ExpiresAt = uint32(qsiResp.ExpiresAt)
	} else if status == http.StatusNoContent {
		log.SpanLog(ctx, log.DebugLevelDmereq, "204 No Content received (session deleted)")
		// This status will be returned in the reply.
	} else if status == http.StatusNotFound {
		log.SpanLog(ctx, log.DebugLevelDmereq, "404 Session not found")
		// This status will be returned in the reply.
	} else if status == http.StatusBadRequest {
		log.SpanLog(ctx, log.DebugLevelDmereq, "400 Bad request")
		return nil, fmt.Errorf(respBody)
	} else {
		log.WarnLog("returning error", "received ", status)
		return nil, fmt.Errorf(fmt.Sprintf("API call received unknown status: %d", status))
	}

	reply.HttpStatus = uint32(status)
	return reply, nil
}

// Convert from the QOS profile names defined in the proto to those used by DTG.
func QosProtoToOperalpha(qosProto string) string {
	switch qosProto {
	case "QOS_NO_PRIORITY":
		return "QOS_NO_PRIORITY"
	case "QOS_LOW_LATENCY":
		return "LOW_LATENCY"
	case "QOS_THROUGHPUT_DOWN_S":
		return "THROUGHPUT_S"
	case "QOS_THROUGHPUT_DOWN_M":
		return "THROUGHPUT_M"
	case "QOS_THROUGHPUT_DOWN_L":
		return "THROUGHPUT_L"
	default:
		return ""
	}
}

// Convert from OPERALPHA's QOS profile names to those defined in the proto.
func QosOperalphaToProto(qosOperalpha string) string {
	switch qosOperalpha {
	case "LOW_LATENCY":
		return "QOS_LOW_LATENCY"
	case "THROUGHPUT_S":
		return "QOS_THROUGHPUT_DOWN_S"
	case "THROUGHPUT_M":
		return "QOS_THROUGHPUT_DOWN_M"
	case "THROUGHPUT_L":
		return "QOS_THROUGHPUT_DOWN_L"
	default:
		return ""
	}
}

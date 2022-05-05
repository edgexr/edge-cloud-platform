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

// Simulator for DT's QOS Priority Session API server. See:
// https://staging-portal.hubraum.opsfactory.dev/de/products/617bd0928431ba00019948f4/summary
// https://staging-portal.hubraum.opsfactory.dev/de/products/617dda988431ba00019948ff/summary

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	sesclient "github.com/edgexr/edge-cloud-infra/operator-api-gw/operalpha/operalpha-sessions/sessionsclient"
)

var (
	port = flag.Int("port", 8081, "listen port")

	indexpath = "/"

	latencyPath    = "/5g-latency/sessions/"
	throughputPath = "/5g-throughput/sessions/"

	// Map of all active sessions keyed on the session ID.
	sessionMap map[string]sesclient.QosSessionResponse
	// All possible QOS profile names for throughput
	qosValuesThroughput [3]string = [3]string{"THROUGHPUT_S", "THROUGHPUT_M", "THROUGHPUT_L"}
)

func printUsage() {
	fmt.Println("\nUsage: \tsessions-server-sim [options]\n\noptions:")
	flag.PrintDefaults()
}

func showIndex(w http.ResponseWriter, r *http.Request) {
	log.Printf("doing showIndex for request: %v\n", r)
	rc := "QOS Priority Sessions server\n"
	rc += latencyPath + " -- Creates, gets, or deletes a Latency priority session\n"
	rc += throughputPath + " -- Creates, gets, or deletes a Throughput priority session\n"
	w.Write([]byte(rc))
}

func latencySession(w http.ResponseWriter, r *http.Request) {
	handleSession(w, r, "latency")
}

func throughputSession(w http.ResponseWriter, r *http.Request) {
	handleSession(w, r, "throughput")
}

func handleSession(w http.ResponseWriter, r *http.Request, priorityType string) {
	log.Println("doing handleSession")
	removeExpiredSessions()
	reqb, err := ioutil.ReadAll(r.Body)
	if err != nil {
		msg := fmt.Sprintf("500 - error reading body: %v\n", err)
		log.Print(msg)
		http.Error(w, msg, 500)
		return
	}
	log.Printf("body: %v\n", string(reqb))

	url := r.RequestURI
	parts := strings.Split(url, "/")

	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		if len(parts) < 4 {
			msg := "400 - Missing sesId"
			log.Print(msg)
			http.Error(w, msg, 400)
			return
		}
		sesId := parts[3]
		log.Printf(r.Method)
		log.Printf("sesId: %v", sesId)
		if sesId == "" {
			msg := "400 - Missing sesId"
			log.Print(msg)
			http.Error(w, msg, 400)
			return
		}
		session, ok := sessionMap[sesId]
		if !ok {
			msg := "404 - Session '" + sesId + "' not found"
			log.Print(msg)
			http.Error(w, msg, 404)
			return
		}
		if r.Method == http.MethodDelete {
			delete(sessionMap, sesId)
			w.WriteHeader(http.StatusNoContent) //204
		} else {
			body, err := json.Marshal(session)
			if err != nil {
				msg := "500 - Unable to marshal JSON response"
				log.Print(msg)
				http.Error(w, msg, 500)
				return
			}
			w.Write(body)
		}

	} else if r.Method == http.MethodPost {
		log.Printf("POST")
		if len(reqb) == 0 {
			msg := "400 - POST Missing JSON body"
			log.Print(msg)
			http.Error(w, msg, 400)
			return
		}
		var req sesclient.QosSessionRequest
		err = json.Unmarshal(reqb, &req)
		if err != nil {
			msg := fmt.Sprintf("400 - json unmarshall error: %v\n", err)
			log.Print(msg)
			http.Error(w, msg, 400)
			return
		}
		log.Printf("unmarshalled body: %v\n", req)
		var missing string
		if req.UeAddr == "" {
			missing += "UeAddr "
		}
		if req.AsAddr == "" {
			missing += "AsAddr "
		}
		if req.AsPorts == "" {
			missing += "AsPorts "
		}
		if req.Qos == "" {
			missing += "Qos "
		}
		if len(missing) > 0 {
			msg := fmt.Sprintf("400 - missing field(s) %s in body: %+v\n", missing, string(reqb))
			log.Print(msg)
			http.Error(w, msg, 400)
			return
		}
		// Make sure a valid QOS value was passed for the given priorityType
		if priorityType == "latency" {
			if req.Qos != "LOW_LATENCY" { // The only valid value
				msg := fmt.Sprintf("400 - Invalid QOS value: %+v\n", req.Qos)
				log.Print(msg)
				http.Error(w, msg, 400)
				return
			}
		} else if priorityType == "throughput" {
			count := 0
			for _, qos := range qosValuesThroughput {
				if req.Qos == qos {
					break
				}
				count++
			}
			if count >= len(qosValuesThroughput) {
				msg := fmt.Sprintf("400 - Invalid QOS value: %+v\n", string(req.Qos))
				log.Print(msg)
				http.Error(w, msg, 400)
				return
			}
		}
		if req.Duration == 0 {
			req.Duration = 86400
		}
		if req.Duration > 86400 {
			msg := fmt.Sprintf("400 - Invalid Duration value: %+v\n", req.Duration)
			log.Print(msg)
			http.Error(w, msg, 400)
			return
		}
		sesId := uuid.New().String()
		log.Printf("Generated new sesId: %s", sesId)
		var resp sesclient.QosSessionResponse
		// Copy common fields from req to resp.
		resp.QosSessionCommon = req.QosSessionCommon
		resp.Id = sesId
		resp.StartedAt = time.Now().Unix()
		resp.ExpiresAt = resp.StartedAt + req.Duration
		log.Printf("resp.StartedAt + req.Duration = resp.ExpiresAt -- %d + %d = %d", resp.StartedAt, req.Duration, resp.ExpiresAt)
		conflict, reason := checkConflict(resp)
		if conflict {
			w.WriteHeader(http.StatusConflict) //409
			w.Write([]byte(reason))
			return
		}

		sessionMap[sesId] = resp
		log.Printf("resp: %v\n", resp)
		body, err := json.Marshal(resp)
		if err != nil {
			msg := "500 - Unable to marshal JSON response"
			log.Print(msg)
			http.Error(w, msg, 500)
		}
		w.WriteHeader(http.StatusCreated) //201
		w.Write(body)
	}
}

func removeExpiredSessions() {
	log.Printf("%d sessions: %v", len(sessionMap), sessionMap)
	for sesId, session := range sessionMap {
		log.Printf("key: %v, element: %v", sesId, session)
		now := time.Now().Unix()
		if now > session.ExpiresAt {
			log.Printf("Deleting %s. Expired by %d seconds", sesId, (now - session.ExpiresAt))
			delete(sessionMap, sesId)
		}
	}
}

// Checks if there is an existing session with the same properties. If so, return reason.
func checkConflict(newSession sesclient.QosSessionResponse) (bool, string) {
	log.Printf("%d sessions: %v", len(sessionMap), sessionMap)
	for sesId, session := range sessionMap {
		log.Printf("key: %v, element: %v", sesId, session)
		if newSession.AsAddr == session.AsAddr &&
			newSession.AsPorts == session.AsPorts &&
			newSession.UeAddr == session.UeAddr &&
			newSession.UePorts == session.UePorts &&
			newSession.ProtocolIn == session.ProtocolIn &&
			newSession.ProtocolOut == session.ProtocolOut {
			log.Printf("Session %s conflicts with request", sesId)
			unixTime := time.Unix(session.ExpiresAt, 0)
			formattedTime := unixTime.Format(time.RFC3339)
			// This error message matches that of DT's API server.
			reason := fmt.Sprintf("Found session %s already active until %s", session.Id, formattedTime)
			return true, reason
		}
	}
	return false, ""
}

func run() {
	http.HandleFunc(indexpath, showIndex)
	http.HandleFunc(latencyPath, latencySession)
	http.HandleFunc(throughputPath, throughputSession)

	log.Printf("Serving paths:")
	log.Printf("    latencyPath=%s", latencyPath)
	log.Printf("    throughputPath=%s", throughputPath)

	sessionMap = make(map[string]sesclient.QosSessionResponse)
	portstr := fmt.Sprintf(":%d", *port)

	log.Printf("Listening on http://127.0.0.1:%d", *port)
	if err := http.ListenAndServe(portstr, nil); err != nil {
		panic(err)
	}
}

func validateArgs() {
	flag.Parse()
	//nothing to check yet
}

func main() {
	validateArgs()
	run()
}

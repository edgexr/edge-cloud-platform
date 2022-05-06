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

package alertmgr

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gorilla/mux"

	"github.com/edgexr/edge-cloud/log"

	//	alertmanager_config "github.com/prometheus/alertmanager/config"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly

	alertmanager_config "github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/config"
)

// Alertmanager config file lock
var configLock sync.RWMutex

const receiverUrlVar string = "receiverName"

// Struct that gets sent between MC and sidecar serbvice in the APIs
type SidecarReceiverConfig struct {
	Receiver alertmanager_config.Receiver `json:"receiver"`
	Route    alertmanager_config.Route    `json:"route,omitempty"`
}

type SidecarReceiverConfigs []SidecarReceiverConfig

type AlertmgrInitInfo struct {
	Email          string
	User           string
	Token          string
	Smtp           string
	Port           string
	Tls            string
	ResolveTimeout string
	PagerDutyUrl   string
}

type SidecarServer struct {
	alertMgrAddr       string
	alertMgrConfigPath string
	httpApiAddr        string
	server             *http.Server
	clientCA           string
	serverCert         string
	certKey            string
	insecureTls        bool
}

func NewSidecarServer(target, path, apiAddr string, initInfo *AlertmgrInitInfo, tlsClient string, tlsServer string, tlsKey string, insecureTls bool) (*SidecarServer, error) {
	server := &SidecarServer{
		alertMgrAddr:       target,
		alertMgrConfigPath: path,
		httpApiAddr:        apiAddr,
		clientCA:           tlsClient,
		serverCert:         tlsServer,
		certKey:            tlsKey,
		insecureTls:        insecureTls,
	}
	if err := server.initAlertmanager(initInfo); err != nil {
		return nil, err
	}
	return server, nil
}

// Get server address with http prefix
func (s *SidecarServer) GetApiAddr() string {
	if !strings.HasPrefix(s.httpApiAddr, "http") {
		return "http://" + s.httpApiAddr
	}
	return s.httpApiAddr
}

func (s *SidecarServer) Run() error {
	rtrMux := mux.NewRouter()
	rtrMux.HandleFunc("/", s.proxyHandler)
	rtrMux.HandleFunc(AlertApi, s.proxyHandler)
	// http.HandleFunc(ReloadConfigApi, proxyHandler) - this should not be externally exposed
	rtrMux.HandleFunc(SilenceApi, s.proxyHandler)
	rtrMux.HandleFunc(ReceiverApi, s.proxyHandler)
	rtrMux.HandleFunc(mobiledgeXReceiversApi, s.alertReceiver).Methods("GET")
	rtrMux.HandleFunc(mobiledgeXReceiverApi, s.alertReceiver)
	rtrMux.HandleFunc(mobiledgeXReceiverApi+"/{"+receiverUrlVar+"}", s.alertReceiver).Methods("GET")
	rtrMux.HandleFunc(mobiledgeXReceiverApi+"/{"+receiverUrlVar+"}", s.alertReceiver).Methods("DELETE")

	listener, err := net.Listen("tcp4", s.httpApiAddr)
	if err != nil {
		return err
	}
	// For unit-tests we request the next available ports, so set it
	s.httpApiAddr = listener.Addr().String()
	s.server = &http.Server{
		Addr:    s.httpApiAddr,
		Handler: rtrMux,
	}
	// detach and run the server
	go func() {
		var err error
		if s.serverCert != "" {
			// if client cert is specified set up cert pool
			if s.clientCA != "" {
				caCertPool := x509.NewCertPool()
				cabs, err := ioutil.ReadFile(s.clientCA)
				if err != nil {
					log.FatalLog("Could not read CA file", "err", err, "CA", s.clientCA)
				}
				ok := caCertPool.AppendCertsFromPEM(cabs)
				if !ok {
					log.FatalLog("Failed to append CA file", "cert", string(cabs))
				}
				tlsConfig := &tls.Config{
					ClientCAs:  caCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
					// For self-signed certs in e2e-testing
					InsecureSkipVerify: s.insecureTls,
				}
				tlsConfig.BuildNameToCertificate()
				s.server.TLSConfig = tlsConfig
			}
			err = s.server.ServeTLS(listener, s.serverCert, s.certKey)
		} else {
			err = s.server.Serve(listener)
		}
		if err != nil && err != http.ErrServerClosed {
			log.FatalLog("Failed to run sidecar server", "err", err)
		}
	}()
	return nil
}

// Simple proxy to the Alertmanager we are connected to
func (s *SidecarServer) proxyHandler(w http.ResponseWriter, r *http.Request) {
	url, err := url.Parse(s.alertMgrAddr)
	if err != nil {
		str := fmt.Sprintf("Proxy URL is not parsable - %s", s.alertMgrAddr)
		http.Error(w, str, http.StatusInternalServerError)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(url)

	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	r.Host = url.Host
	proxy.ServeHTTP(w, r)
}

func (s *SidecarServer) alertReceiver(w http.ResponseWriter, req *http.Request) {
	var writeConfig bool

	span := log.StartSpan(log.DebugLevelApi|log.DebugLevelInfo, "Alertmgr Sidecar Receiver")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	// read file and grab a lock
	config, err := s.readAlertManagerConfigAndLock(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to read config request", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeConfig = false
	switch req.Method {
	case http.MethodGet:
		// Show Receivers
		configLock.Unlock()
		// get the receiver name
		vars := mux.Vars(req)
		receiverName, filterOnName := vars[receiverUrlVar]

		receivers := SidecarReceiverConfigs{}
		for ii, rec := range config.Receivers {
			if rec.Name == "default" {
				continue
			}
			// Check the filter
			if filterOnName {
				curRecName, err := getAlertReceiverFromName(rec.Name)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "Unable to parse receiver", "err", err, "receiver", rec)
					continue
				}
				if receiverName != curRecName.Name {
					// Filter does not match
					continue
				}
			}
			recConfig := SidecarReceiverConfig{
				Receiver: *config.Receivers[ii],
			}
			for jj, route := range config.Route.Routes {
				if route.Receiver == rec.Name {
					recConfig.Route = *config.Route.Routes[jj]
					receivers = append(receivers, recConfig)
					break
				}
			}
		}

		// marshal data and send it back
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(receivers)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to get marshal Receiver Config data", "err", err,
				"cfg", receivers)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	case http.MethodPost:
		// Create receiver
		defer configLock.Unlock()
		receiverConfig := SidecarReceiverConfig{}
		err = json.NewDecoder(req.Body).Decode(&receiverConfig)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to decode request", "method", req.Method,
				"url", req.URL, "payload", req.Body)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeConfig = true
		for _, rec := range config.Receivers {
			if rec.Name == receiverConfig.Receiver.Name {
				log.SpanLog(ctx, log.DebugLevelInfo, "Receiver Exists - delete it first")
				http.Error(w, "Receiver Exists - delete it first", http.StatusConflict)
				return
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "Adding alert receiver", "receiver", receiverConfig.Receiver, "route", receiverConfig.Route)
		config.Receivers = append(config.Receivers, &receiverConfig.Receiver)
		config.Route.Routes = append(config.Route.Routes, &receiverConfig.Route)
	case http.MethodDelete:
		// Delete receiver
		defer configLock.Unlock()
		// get the receiver name
		vars := mux.Vars(req)
		receiverName, ok := vars[receiverUrlVar]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "Receiver Name not specified", "method", req.Method,
				"url", req.URL)
			http.Error(w, "Receiver name not specified", http.StatusBadRequest)
			return
		}
		for ii, rec := range config.Receivers {
			if rec.Name == receiverName {
				log.SpanLog(ctx, log.DebugLevelInfo, "Found Receiver - now delete it")
				// remove from the receivers
				config.Receivers = append(config.Receivers[:ii],
					config.Receivers[ii+1:]...)
				// remove from routes
				for jj, route := range config.Route.Routes {
					if route.Receiver == receiverName {
						config.Route.Routes = append(config.Route.Routes[:jj],
							config.Route.Routes[jj+1:]...)
						break
					}
				}
				// found something to delete
				writeConfig = true
				break
			}
		}
		// We did not find the receiver - should return an error
		if !writeConfig {
			log.SpanLog(ctx, log.DebugLevelInfo, "Could not find a receiver", "receiver", receiverName)
			recSent, err := getAlertReceiverFromName(receiverName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			errStr := fmt.Sprintf("No receiver \"%s\" of type %s and severity %s for user \"%s\"",
				recSent.Name, recSent.Type, recSent.Severity, recSent.User)
			http.Error(w, errStr, http.StatusNotFound)
			return
		}
	default:
		log.SpanLog(ctx, log.DebugLevelInfo, "Unsupported method", "method", req.Method,
			"url", req.URL)
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
		return
	}
	// No need to write config
	if !writeConfig {
		return
	}
	// write config out
	// NOTE: Alertmanager native unmarshal hides smtp password when marshalling.
	// See: https://github.com/prometheus/alertmanager/issues/1985
	// Instead our copy of the unmarshal code does not hide this. Hopefully 1985 will get addressed at some point
	err = s.writeAlertmanagerConfigLocked(ctx, bytes.NewBufferString(config.String()))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to write alertmanager configuration", "err", err, "config", config.String())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// trigger reload of the config
	res, err := alertMgrApi(ctx, s.alertMgrAddr, "POST", ReloadConfigApi, "", nil, nil)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to reload alertmanager config", "err", err, "result", res)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *SidecarServer) initAlertmanager(initInfo *AlertmgrInitInfo) error {
	var err error
	span := log.StartSpan(log.DebugLevelApi|log.DebugLevelInfo, "Alertmgr Sidecar Init")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	//  Make sure config file is in the good condition prior to connecting
	if err = s.initConfigFile(ctx, initInfo); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Unable to init config file", "err", err, "initInfo", initInfo)
		return err
	}

	// wait for alertmanager to be up first
	for ii := 0; ii < 10; ii++ {
		_, err = alertMgrApi(ctx, s.alertMgrAddr, "GET", "", "", nil, nil)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to connect to alertmanager", "err", err)
		return err
	}
	// Connected to alertmanager - trigger a reload to make sure latest config changes were picked up
	res, err := alertMgrApi(ctx, s.alertMgrAddr, "POST", ReloadConfigApi, "", nil, nil)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to reload alertmanager config", "err", err, "result", res)
		return err
	}
	return nil
}

// Read config from the alertmgr config file.
// There are two passes here - one if a file exists and another if a file exists,
// but doesn't contain required fields
func (s *SidecarServer) initConfigFile(ctx context.Context, info *AlertmgrInitInfo) error {
	// grab config lock
	configLock.Lock()
	defer configLock.Unlock()
	// Check that the config File exists
	file, err := os.Open(s.alertMgrConfigPath)
	if err != nil {
		// Doesn't exist - need to load up a default config
		if os.IsNotExist(err) {
			log.SpanLog(ctx, log.DebugLevelInfo, "Loading default config - no file found")
			if err = s.loadDefaultConfigFileLocked(ctx, info); err != nil {
				return err
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to access alertmanager config", "err", err, "file", s.alertMgrConfigPath)
			return err
		}
	}
	file.Close()
	// Read config
	config, err := alertmanager_config.LoadFile(s.alertMgrConfigPath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to parse alertmanager config file", "err", err,
			"file", s.alertMgrConfigPath)
		return err
	}
	// Make sure that smtp defails are present
	if config.Global.SMTPSmarthost.Host == "" || config.Global.SMTPFrom == "" {
		log.SpanLog(ctx, log.DebugLevelInfo, "Writing correct default file")
		if err = s.loadDefaultConfigFileLocked(ctx, info); err != nil {
			return err
		}
		// Read config
		config, err = alertmanager_config.LoadFile(s.alertMgrConfigPath)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to parse alertmanager config file", "err", err,
				"file", s.alertMgrConfigPath)
			return err
		}
	}
	return nil
}

// Load default configuration into Alertmanager
// Note configLock should be held prior to calling this
func (s *SidecarServer) loadDefaultConfigFileLocked(ctx context.Context, info *AlertmgrInitInfo) error {
	defaultConfigTemplate = template.Must(template.New("alertmanagerconfig").Parse(DefaultAlertmanagerConfigT))
	config := bytes.Buffer{}
	if err := defaultConfigTemplate.Execute(&config, info); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to parse the config template", "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "Loading default config", "config", config.String())
	return s.writeAlertmanagerConfigLocked(ctx, &config)
}

// Note - we should hold configLock prior to calling this function
func (s *SidecarServer) writeAlertmanagerConfigLocked(ctx context.Context, config *bytes.Buffer) error {
	err := ioutil.WriteFile(s.alertMgrConfigPath, config.Bytes(), 0644)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to write default alertmanager config", "err", err, "file", s.alertMgrConfigPath)
		return err
	}
	if runtime.GOOS == "darwin" {
		// probably because of the way docker uses VMs on mac,
		// the file watch doesn't detect changes done to the targets
		// file in the host.
		cmd := exec.Command("docker", "exec", "alertmanager", "touch", "/etc/prometheus/alertmanager.yml")
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to touch alertmgr file in container to trigger refresh in alertmanager", "out", string(out), "err", err)
		}
	}
	return nil
}

// Note - this grabs configLock
func (s *SidecarServer) readAlertManagerConfigAndLock(ctx context.Context) (*alertmanager_config.Config, error) {
	// grab config lock
	configLock.Lock()

	// Read config
	config, err := alertmanager_config.LoadFile(s.alertMgrConfigPath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to parse alertmanager config file", "err", err,
			"file", s.alertMgrConfigPath)
		return nil, err
	}
	return config, nil
}

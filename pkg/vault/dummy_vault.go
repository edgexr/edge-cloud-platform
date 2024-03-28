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

package vault

import (
	_ "embed"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/hashicorp/vault/api"
)

//go:embed setup.sh
var SetupScript []byte

//go:embed setup-region.sh
var SetupRegionScript []byte

type DummyServer struct {
	TestServer *httptest.Server
	Config     *Config
	KVStore    map[string]map[string]interface{}
}

// NewDummServer for unit testing
func NewDummyServer() *DummyServer {
	s := DummyServer{
		KVStore: make(map[string]map[string]interface{}),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			data, ok := s.KVStore[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				log.Printf("DummyVault GET %s: not found", r.URL.Path)
				return
			}
			msg := map[string]interface{}{
				"data": data,
			}
			out, err := json.Marshal(msg)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				log.Printf("DummyVault GET %s: %s", r.URL.Path, err)
				return
			}
			w.Write(out)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			log.Printf("DummyVault GET %s: %v", r.URL.Path, string(out))
		case http.MethodPost:
			fallthrough
		case http.MethodPut:
			defer r.Body.Close()
			in, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				log.Printf("DummyVault %s %s: %s", r.Method, r.URL.Path, err)
				return
			}
			data := map[string]interface{}{}
			err = json.Unmarshal(in, &data)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				log.Printf("DummyVault %s %s: %s", r.Method, r.URL.Path, err)
				return
			}
			s.KVStore[r.URL.Path] = data
			w.WriteHeader(http.StatusOK)
			log.Printf("DummyVault %s %s: %v", r.Method, r.URL.Path, string(in))
		case http.MethodDelete:
			// delete path is metadata
			path := strings.Replace(r.URL.Path, "/metadata/", "/data/", 1)
			delete(s.KVStore, path)
			w.WriteHeader(http.StatusOK)
			log.Printf("DummyVault DELETE %s", r.URL.Path)
		}
	}))
	s.TestServer = server
	s.Config = NewConfig(server.URL, &NoAuth{})
	return &s
}

// NoAuth skips any auth. It is used for unit testing against a fake httptest server.
type NoAuth struct{}

func (s *NoAuth) Login(client *api.Client) error {
	return nil
}

func (s *NoAuth) Type() string {
	return "none"
}

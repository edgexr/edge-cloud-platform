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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/edgeturnclient"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	edgetls "github.com/edgexr/edge-cloud-platform/pkg/tls"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"github.com/xtaci/smux"
)

func setupConsoleStream(sess *smux.Session, consoleUrlHost string, isTLS bool) error {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err.Error() != io.ErrClosedPipe.Error() {
				return fmt.Errorf("failed to setup smux acceptstream, %v", err)
			}
			return nil
		}
		var server net.Conn
		if isTLS {
			server, err = tls.Dial("tcp", consoleUrlHost, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err != nil {
				return fmt.Errorf("failed to get console, %v", err)
			}
		} else {
			server, err = net.Dial("tcp", consoleUrlHost)
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
}

func TestEdgeTurnServer(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi | log.DebugLevelInfo)
	log.InitTracer(nil)
	defer log.FinishTracer()
	flag.Parse() // set defaults

	*testMode = true
	ctx := log.StartTestSpan(context.Background())

	turnLis, err := setupTurnServer(ctx)
	require.Nil(t, err)
	defer turnLis.Close()

	proxyMux := http.NewServeMux()
	proxyServer, err := setupProxyServer(ctx, proxyMux)
	require.Nil(t, err)
	defer proxyServer.Shutdown(context.Background())

	// Test session info received for ExecReqShell
	// CRM connection to EdgeTurn
	tlsConfig, err := edgetls.GetLocalTLSConfig()
	require.Nil(t, err, "get local tls config")
	turnConn, err := tls.Dial("tcp", "127.0.0.1:6080", tlsConfig)
	require.Nil(t, err, "connect to EdgeTurn server")
	defer turnConn.Close()

	// Send ExecReqInfo to EdgeTurn Server
	execReqInfo := cloudcommon.ExecReqInfo{
		Type: cloudcommon.ExecReqShell,
	}
	out, err := json.Marshal(&execReqInfo)
	require.Nil(t, err, "marshal ExecReqInfo")
	_, err = turnConn.Write(out)
	require.Nil(t, err, "send ExecReqInfo to EdgeTurn server")

	// EdgeTurn Server should reply with SessionInfo
	var sessInfo cloudcommon.SessionInfo
	d := json.NewDecoder(turnConn)
	err = d.Decode(&sessInfo)
	require.Nil(t, err, "decode session info from EdgeTurn server")
	require.NotEqual(t, "", sessInfo.Token, "token is not empty")

	proxyVal := TurnProxy.Get(sessInfo.Token)
	require.NotNil(t, proxyVal, "proxyValue is present, hence not nil")
	require.NotNil(t, proxyVal.CrmConn, "crm connection is not nil")

	// Client connection to EdgeTurn
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	ws, _, err := dialer.Dial("wss://127.0.0.1:8443/edgeshell?edgetoken="+sessInfo.Token, nil)
	require.Nil(t, err, "client websocket connection to EdgeTurn server")
	err = ws.WriteMessage(websocket.TextMessage, []byte("test msg1"))
	require.Nil(t, err, "client write message to EdgeTurn server")
	buf := make([]byte, 50)
	n, err := turnConn.Read(buf)
	require.Nil(t, err, "read from EdgeTurn connection")
	require.Equal(t, "test msg1", string(buf[:n]), "received message from client")

	_, err = turnConn.Write([]byte("test msg2"))
	require.Nil(t, err, "write to EdgeTurn connection")

	_, msg, err := ws.ReadMessage()
	require.Nil(t, err, "client read message from EdgeTurn server")
	require.Equal(t, "test msg2", string(msg), "received message from crm")

	// Client closes connection, this should cleanup connection
	// from EdgeTurn server side as well
	ws.Close()
	time.Sleep(1 * time.Second)

	proxyVal = TurnProxy.Get(sessInfo.Token)
	require.Nil(t, proxyVal, "proxyValue should not exist as client exited")

	// Test edge console
	// =================
	isTLS := true
	testEdgeTurnConsole(t, isTLS)
	testEdgeTurnConsole(t, !isTLS)
}

func testEdgeTurnConsole(t *testing.T, isTLS bool) {
	// Start local console server
	var consoleServer *httptest.Server
	if isTLS {
		consoleServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proto, found := r.Header["X-Forwarded-Proto"]
			require.True(t, found, "found x-forwarded-proto header")
			require.Equal(t, proto[0], "https")
			fmt.Fprintln(w, "Console Content")
		}))
	} else {
		consoleServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proto, found := r.Header["X-Forwarded-Proto"]
			require.True(t, found, "found x-forwarded-proto header")
			require.Equal(t, proto[0], "http")
			fmt.Fprintln(w, "Console Content")
		}))
	}
	require.NotNil(t, consoleServer, "start console server")
	defer consoleServer.Close()
	consoleURL := consoleServer.URL + "?token=xyz"
	initURL, err := url.Parse(consoleURL)
	require.Nil(t, err)
	// Test session info received for ExecReqShell
	// CRM connection to EdgeTurn
	tlsConfig, err := edgetls.GetLocalTLSConfig()
	require.Nil(t, err, "get local tls config")
	turnConn1, err := tls.Dial("tcp", "127.0.0.1:6080", tlsConfig)
	require.Nil(t, err, "connect to EdgeTurn server")
	defer turnConn1.Close()
	// Send ExecReqInfo to EdgeTurn Server
	execReqInfo := cloudcommon.ExecReqInfo{
		Type:    cloudcommon.ExecReqConsole,
		InitURL: initURL,
	}
	out, err := json.Marshal(&execReqInfo)
	require.Nil(t, err, "marshal ExecReqInfo")
	_, err = turnConn1.Write(out)
	require.Nil(t, err, "send ExecReqInfo to EdgeTurn server")

	// EdgeTurn Server should reply with SessionInfo
	var sessInfo cloudcommon.SessionInfo
	d := json.NewDecoder(turnConn1)
	err = d.Decode(&sessInfo)
	require.Nil(t, err, "decode session info from EdgeTurn server")
	require.NotEqual(t, "", sessInfo.Token, "token is not empty")

	proxyVal := TurnProxy.Get(sessInfo.Token)
	require.NotNil(t, proxyVal, "proxyValue is present, hence not nil")
	require.NotNil(t, proxyVal.CrmConn, "crm connection is not nil")
	fmt.Printf("Token is %s\n", sessInfo.Token)

	// setup SMUX connection to console server
	sess, err := smux.Server(turnConn1, nil)
	require.Nil(t, err, "setup smux server")
	go setupConsoleStream(sess, initURL.Host, isTLS)
	defer sess.Close()

	contents, err := edgeturnclient.ReadConsoleURL("https://127.0.0.1:8443/edgeconsole?edgetoken="+sessInfo.Token, nil)
	require.Nil(t, err)
	require.Equal(t, string(contents), "Console Content\n")
}

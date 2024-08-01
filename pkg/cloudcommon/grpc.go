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

package cloudcommon

import (
	"context"
	ctls "crypto/tls"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/tls"
	gwruntime "github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

func ParseGrpcMethod(method string) (path string, cmd string) {
	if i := strings.LastIndexByte(method, '/'); i > 0 {
		path = method[:i]
		cmd = method[i+1:]
	} else {
		path = ""
		cmd = method
	}
	return path, cmd
}

type GrpcGWConfig struct {
	ApiAddr        string
	GetCertificate func(*ctls.CertificateRequestInfo) (*ctls.Certificate, error)
	TlsCertFile    string
	ApiHandles     []func(context.Context, *gwruntime.ServeMux, *grpc.ClientConn) error
}

func GrpcGateway(cfg *GrpcGWConfig) (http.Handler, error) {
	ctx := context.Background()
	// GRPC GW does not validate the GRPC server cert because it may be public signed and therefore
	// may not work with internal addressing
	skipVerify := true
	tlsMode := tls.MutualAuthTLS
	if cfg.GetCertificate == nil && cfg.TlsCertFile == "" {
		tlsMode = tls.NoTLS
	}
	dialOption, err := tls.GetTLSClientDialOption(tlsMode, cfg.ApiAddr, cfg.GetCertificate, cfg.TlsCertFile, skipVerify)
	if err != nil {
		log.FatalLog("Unable to get TLSClient Dial Option", "error", err)
	}
	conn, err := grpc.DialContext(ctx, cfg.ApiAddr, dialOption)
	if err != nil {
		log.FatalLog("Failed to start REST gateway", "error", err)
	}
	mux := gwruntime.NewServeMux(
		// this is necessary to get error details properly
		// marshalled in unary requests
		gwruntime.WithProtoErrorHandler(gwruntime.DefaultHTTPProtoErrorHandler),
	)
	for _, f := range cfg.ApiHandles {
		if err := f(ctx, mux, conn); err != nil {
			return nil, err
		}
	}
	return mux, nil
}

func GrpcGatewayServe(server *http.Server, tlsCertFile string) {
	// Serve REST gateway
	cfg := server.TLSConfig
	if cfg == nil || (cfg.GetCertificate == nil && tlsCertFile == "") {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.FatalLog("Failed to serve HTTP", "error", err)
		}
	} else if cfg.GetCertificate != nil {
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.FatalLog("Failed to serve HTTP TLS", "error", err)
		}
	} else {
		tlsKeyFile := strings.Replace(tlsCertFile, ".crt", ".key", -1)
		if err := server.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != http.ErrServerClosed {
			log.FatalLog("Failed to serve HTTP TLS", "error", err)
		}
	}
}

func GrpcCreds(cfg *ctls.Config) grpc.ServerOption {
	if cfg == nil {
		return grpc.Creds(nil)
	} else {
		return grpc.Creds(credentials.NewTLS(cfg))
	}
}

// Keepalive parameters to close the connection if the other end
// goes away unexpectedly. The server and client parameters must be balanced
// correctly or the connection may be closed incorrectly.
const (
	infinity   = time.Duration(math.MaxInt64)
	kpInterval = 30 * time.Second
)

var GRPCServerKeepaliveParams = keepalive.ServerParameters{
	MaxConnectionIdle:     3 * kpInterval,
	MaxConnectionAge:      infinity,
	MaxConnectionAgeGrace: infinity,
	Time:                  kpInterval,
	Timeout:               kpInterval,
}
var GRPCClientKeepaliveParams = keepalive.ClientParameters{
	Time:    kpInterval,
	Timeout: kpInterval,
}
var GRPCServerKeepaliveEnforcement = keepalive.EnforcementPolicy{
	MinTime: 1 * time.Second,
}

// GRPCError unwraps status.Status errors, this avoids
// ugly type print outs when various library code converts
// the error to a string.
func GRPCErrorUnwrap(err error) error {
	st, ok := status.FromError(err)
	if ok && st != nil {
		return errors.New(st.Message())
	}
	return err
}

type GRPCStreamRecv[Object any] interface {
	Recv() (Object, error)
}

// StreamRecv converts a grpc stream receiver into callbacks
func StreamRecv[Object any](ctx context.Context, stream GRPCStreamRecv[Object], cb func(obj Object) error) error {
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return GRPCErrorUnwrap(err)
		}
		err = cb(obj)
		if err != nil {
			return err
		}
	}
	return nil
}

type StatusObj interface {
	GetStatus() *edgeproto.StatusInfo
}

// StreamRecvWithStatus is like StreamRecv, but for objects that include
// a StatusInfo object whose new status messages should be sent via the
// statusSend callback.
func StreamRecvWithStatus[Object StatusObj](ctx context.Context, stream GRPCStreamRecv[Object], statusSend func(*edgeproto.Result) error, cb func(obj Object) error) error {
	lastMsgCnt := 0
	return StreamRecv(ctx, stream, func(obj Object) error {
		cb(obj)

		status := obj.GetStatus()
		if status != nil {
			for ii := lastMsgCnt; ii < len(status.Msgs); ii++ {
				err := statusSend(&edgeproto.Result{
					Message: status.Msgs[ii],
				})
				if err != nil {
					return err
				}
			}
			lastMsgCnt = len(status.Msgs)
		}
		return nil
	})
}

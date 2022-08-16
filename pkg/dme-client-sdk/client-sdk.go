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
	"log"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address = "localhost:50051"
	version = 1
)

func main() {
	// Set up a connection to the server
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithDefaultCallOptions(grpc.ForceCodec(&cloudcommon.ProtoCodec{})))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	sessionClient := dme.NewSessionClient(conn)
	appClient := dme.NewMatchEngineApiClient(conn)
	locClient := dme.NewLocationClient(conn)

	_, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	FindCloudlets(sessionClient, appClient)
	TestLocations(sessionClient, locClient)
}

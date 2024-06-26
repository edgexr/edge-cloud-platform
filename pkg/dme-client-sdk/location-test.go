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
	"fmt"
	"log"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	uaemtest "github.com/edgexr/edge-cloud-platform/pkg/uaem-testutil"
	"golang.org/x/net/context"
)

func TestLocations(sessionClient dme.SessionClient, locClient dme.LocationClient) {
	ctx, _ := context.WithTimeout(context.Background(), time.Second)

	fmt.Println(">>>>>>>Finding Right Locations<<<<<<<<<")
	for _, m := range uaemtest.VerifyLocData {
		// Register the client first
		mstatus, err := sessionClient.RegisterClient(ctx, &m.Reg)
		if err != nil {
			log.Fatalf("could not register: %v", err)
		}
		m.Req.SessionCookie = mstatus.SessionCookie
		mreply, err := locClient.VerifyLocation(ctx, &m.Req)
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		fmt.Printf("Verify Loc = %f/%f status %d\n",
			m.Req.GpsLocation.Latitude, m.Req.GpsLocation.Longitude,
			mreply.GpsLocationStatus)
	}
}

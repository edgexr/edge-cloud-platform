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

package simulatedlocation

import (
	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	uaemcommon "github.com/edgexr/edge-cloud-platform/pkg/uaem-common"
)

var fakeLocation = dme.Loc{Latitude: 32.013988, Longitude: -96.598243}

// VerifySimulatedClientLoc uses a fixed position for the "real" location of the client and tests against that
func VerifySimulatedClientLoc(mreq *dme.VerifyLocationRequest, mreply *dme.VerifyLocationReply) error {

	mreply.GpsLocationStatus = dme.VerifyLocationReply_LOC_UNKNOWN
	mreply.GpsLocationAccuracyKm = -1

	distance := uaemcommon.DistanceBetween(*mreq.GpsLocation, fakeLocation)

	//here we want the verified range of the distance based on the distance rules
	//e.g. if the actual distance is 50KM we may return a range to say within 100KM
	locresult := uaemcommon.GetLocationResultForDistance(distance)
	locval := uaemcommon.GetDistanceAndStatusForLocationResult(locresult)

	mreply.GpsLocationStatus = locval.MatchEngineLocStatus
	mreply.GpsLocationAccuracyKm = locval.DistanceRange

	log.DebugLog(log.DebugLevelDmereq, "verified location at",
		"lat", mreq.GpsLocation.Latitude,
		"long", mreq.GpsLocation.Longitude,
		"actual distance", distance,
		"distance range", mreply.GpsLocationAccuracyKm,
		"status", mreply.GpsLocationStatus)

	return nil
}

func GetSimulatedClientLoc(mreq *dme.GetLocationRequest, reply *dme.GetLocationReply) error {
	reply.CarrierName = mreq.CarrierName
	reply.Status = dme.GetLocationReply_LOC_FOUND
	reply.NetworkLocation = &fakeLocation
	return nil
}

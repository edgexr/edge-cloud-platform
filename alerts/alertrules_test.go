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

package alerts

import (
	"testing"

	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

func TestGetPromAlertFromEdgeprotoAlert(t *testing.T) {
	appInst := testutil.AppInstData[0]

	// test non-default description alert
	alert := testutil.AlertPolicyData[0]
	rule := getPromAlertFromEdgeprotoAlert(&appInst, &alert)
	require.Equal(t, alert.Key.Name, rule.Alert, "Alert name should match")
	require.Equal(t, alert.Description, rule.Annotations[cloudcommon.AlertAnnotationDescription],
		"Descrition should match the configured one")
	require.Equal(t, alert.Key.Name, rule.Annotations[cloudcommon.AlertAnnotationTitle],
		"Title is Alert Name")

	// test default description with a single trigger
	alert = testutil.AlertPolicyData[1]
	rule = getPromAlertFromEdgeprotoAlert(&appInst, &alert)
	require.Equal(t, alert.Key.Name, rule.Alert, "Alert name should match")
	expectedDescription := "Number of active connections > 10"
	require.Equal(t, expectedDescription, rule.Annotations[cloudcommon.AlertAnnotationDescription],
		"Testing generated description[single trigger]")
	require.Equal(t, alert.Key.Name, rule.Annotations[cloudcommon.AlertAnnotationTitle],
		"Title is Alert Name")

	// test default description with multiple triggers
	alert = testutil.AlertPolicyData[3]
	rule = getPromAlertFromEdgeprotoAlert(&appInst, &alert)
	require.Equal(t, alert.Key.Name, rule.Alert, "Alert name should match")
	expectedDescription = "CPU Utilization > 80% and Memory Utilization > 80%"
	require.Equal(t, expectedDescription, rule.Annotations[cloudcommon.AlertAnnotationDescription],
		"Testing generated description[multiple triggers]")
	require.Equal(t, alert.Key.Name, rule.Annotations[cloudcommon.AlertAnnotationTitle],
		"Title is Alert Name")

	// test title and description as annotations
	alert = testutil.AlertPolicyData[4]
	rule = getPromAlertFromEdgeprotoAlert(&appInst, &alert)
	require.Equal(t, alert.Key.Name, rule.Alert, "Alert name should match")
	require.Equal(t, alert.Annotations[cloudcommon.AlertAnnotationDescription],
		rule.Annotations[cloudcommon.AlertAnnotationDescription], "Description is in annotations")
	require.Equal(t, alert.Annotations[cloudcommon.AlertAnnotationTitle],
		rule.Annotations[cloudcommon.AlertAnnotationTitle], "Title is in annotations")
}

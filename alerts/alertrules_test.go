package alerts

import (
	"testing"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/testutil"
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

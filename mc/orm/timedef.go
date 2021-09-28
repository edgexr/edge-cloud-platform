package orm

import (
	fmt "fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const (
	// TODO: use actual settings value
	DefaultAppInstTimeWindow     = 15 * time.Second
	DefaultClientApiTimeWindow   = 30 * time.Second
	DefaultClientUsageTimeWindow = 60 * time.Minute
	FallbackTimeRange            = 12 * time.Hour
)

func getTimeDefinition(obj *ormapi.MetricsCommon, minTimeWindow time.Duration) string {
	duration := getTimeDefinitionDuration(obj, minTimeWindow)
	if duration <= 0 {
		return ""
	}
	return duration.String()
}

func getTimeDefinitionDuration(obj *ormapi.MetricsCommon, minTimeWindow time.Duration) time.Duration {
	// In case we are requesting last n number of entries and don't provide time window
	// we should skip the function and time-based grouping
	if obj.Limit != 0 {
		return 0
	}
	// If start time is past end time, cannot group by time
	timeDiff := obj.EndTime.Sub(obj.StartTime)
	if timeDiff < 0 {
		return 0
	}
	// Make sure we don't have any fractional seconds in here
	timeWindow := time.Duration(timeDiff / time.Duration(obj.NumSamples)).Truncate(time.Second)
	if timeWindow < minTimeWindow {
		return minTimeWindow
	}
	return timeWindow
}

func validateMetricsCommon(obj *ormapi.MetricsCommon) error {
	// return error if both Limit and NumSamples are set
	if obj.Limit != 0 && obj.NumSamples != 0 {
		return fmt.Errorf("Only one of Limit or NumSamples can be specified")
	}

	// return error if Limit is a negative value
	if obj.Limit < 0 {
		return fmt.Errorf("Limit cannot be negative")
	}

	// return error if NumSamples is a negative value
	if obj.NumSamples < 0 {
		return fmt.Errorf("NumSamples cannot be negative")
	}

	// populate one of Last or NumSamples if neither are set
	if obj.Limit == 0 && obj.NumSamples == 0 {
		if obj.StartTime.IsZero() && obj.EndTime.IsZero() {
			// fallback to Limit if nothing is in MetricsCommon is set
			obj.Limit = maxEntriesFromInfluxDb
		} else {
			// fallback to NumSamples/Time Definition if start and end times are set
			obj.NumSamples = maxEntriesFromInfluxDb
		}
	}

	// If the limit is set, and no start/end time/age, don't add it
	if obj.Limit != 0 &&
		obj.StartTime.IsZero() && obj.EndTime.IsZero() &&
		obj.StartAge == 0 && obj.EndAge == 0 {
		return nil
	}
	// resolve and fill in time fields
	if err := obj.Resolve(FallbackTimeRange); err != nil {
		return err
	}
	return nil
}

package ormapi

import (
	"strconv"
	"time"
)

// microseconds since unix epoch
type TimeMicroseconds uint64
type DurationMicroseconds uint64

const (
	Second      int64 = 1
	Millisecond       = 1000 * Second
	Microsecond       = 1000 * Millisecond
	Nanosecond        = 1000 * Microsecond

	TimeFormatDate        = "2006/01/02"
	TimeFormatDateTime    = "01-02 15:04:05"
	TimeFormatDayDateTime = "Mon Jan 2 15:04:05"
)

// It is intentional to not define custom marshalers for JSON.
// This is so JSON data returned by MC to clients (UI, mcctl, etc)
// remains in it's original form. It is up to the client to
// transform the original data into a displayable format consumable
// by the user. The backend should not do any such transformation.
// If the client needs a JSON transformation, it will need to define
// it's own struct type with custom marshalers.

func (s *TimeMicroseconds) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	i, err := strconv.ParseUint(str, 10, 64)
	if err == nil {
		*s = TimeMicroseconds(i)
		return nil
	}
	tt := time.Time{}
	err = tt.UnmarshalText([]byte(str))
	if err != nil {
		return err
	}
	s.FromTime(tt)
	return nil
}

func (s TimeMicroseconds) MarshalYAML() (interface{}, error) {
	sec := int64(s) / int64(Microsecond)
	nsec := (int64(s) % int64(Microsecond)) * int64(1000)
	tt := time.Unix(sec, nsec)
	byt, err := tt.MarshalText()
	if err != nil {
		return nil, err
	}
	return string(byt), nil
}

func (s *TimeMicroseconds) FromTime(tt time.Time) {
	*s = TimeMicroseconds(tt.Unix() * int64(Microsecond))
	*s = *s + TimeMicroseconds(tt.Nanosecond()/1000)
}

func (s *DurationMicroseconds) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	i, err := strconv.ParseUint(str, 10, 64)
	if err == nil {
		*s = DurationMicroseconds(i)
		return nil
	}
	dur, err := time.ParseDuration(str)
	if err != nil {
		return err
	}
	*s = DurationMicroseconds(dur.Nanoseconds() / 1000)
	return nil
}

func (s DurationMicroseconds) MarshalYAML() (interface{}, error) {
	dur := time.Duration(s * 1000)
	return dur.String(), nil
}

func DateCmpUTC(date1, date2 time.Time) int {
	y1, m1, d1 := date1.UTC().Date()
	y2, m2, d2 := date2.UTC().Date()
	if y1-y2 != 0 {
		return y1 - y2
	}
	if m1-m2 != 0 {
		return int(m1 - m2)
	}
	if d1-d2 != 0 {
		return d1 - d2
	}
	return 0
}

func IsUTCTimezone(date time.Time) bool {
	tz, offset := date.Zone()
	if tz != "UTC" || offset != 0 {
		return false
	}
	return true
}

func StripTimeUTC(date time.Time) time.Time {
	utcDate := date.UTC()
	return time.Date(utcDate.Year(), utcDate.Month(), utcDate.Day(), 0, 0, 0, 0, time.UTC)
}

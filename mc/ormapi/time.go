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

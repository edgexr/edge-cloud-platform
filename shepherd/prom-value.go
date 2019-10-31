package main

import (
	"encoding/json"
	"strconv"
)

// Prometheus Alert Value may be a string or a numeric, depending on
// the version of the prometheus operator used. Handle either.
type PromValue float64

func (s PromValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(float64(s))
}

func (s *PromValue) UnmarshalJSON(b []byte) error {
	var val float64
	err := json.Unmarshal(b, &val)
	if err == nil {
		*s = PromValue(val)
		return nil
	}
	var str string
	err = json.Unmarshal(b, &str)
	if err == nil {
		val, err = strconv.ParseFloat(str, 64)
		if err == nil {
			*s = PromValue(val)
			return nil
		}
		return err
	}
	return err
}

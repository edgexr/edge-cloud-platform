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

package k8smgmt

import (
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestQuantityToUdec64(t *testing.T) {
	tests := []struct {
		qStr   string
		whole  uint64
		nanos  uint32
		expErr string
	}{
		{"0", 0, 0, ""},
		{"1", 1, 0, ""},
		{"1.9", 1, 900 * edgeproto.DecMillis, ""},
		{"1.900", 1, 900 * edgeproto.DecMillis, ""},
		{"1900m", 1, 900 * edgeproto.DecMillis, ""},
		{"1.001", 1, 1 * edgeproto.DecMillis, ""},
		{"0.010", 0, 10 * edgeproto.DecMillis, ""},
		{"1M", 1000 * 1000, 0, ""},
		{"1.1M", 1100 * 1000, 0, ""},
		{"1Mi", 1024 * 1024, 0, ""},
		{"20G", 20 * 1000 * 1000 * 1000, 0, ""},
		{"20Gi", 20 * 1024 * 1024 * 1024, 0, ""},
		{"-1", 0, 0, "Cannot assign negative"},
		{"-0.001", 0, 0, "Cannot assign negative"},
	}
	for _, test := range tests {
		q := resource.MustParse(test.qStr)
		actDec, err := QuantityToUdec64(q)
		if test.expErr == "" {
			require.Nil(t, err)
			expDec := edgeproto.NewUdec64(test.whole, test.nanos)
			require.Equal(t, expDec, actDec)
		} else {
			require.NotNil(t, err)
			require.Contains(t, err.Error(), test.expErr)
		}
	}
}

func TestQuantityToUint64(t *testing.T) {
	tests := []struct {
		qStr   string
		expVal uint64
		expErr string
	}{
		{"0", 0, ""},
		{"1", 1, ""},
		{"1M", 1000 * 1000, ""},
		{"1Mi", 1024 * 1024, ""},
		{"20Gi", 20 * 1024 * 1024 * 1024, ""},
		{"0.1", 0, "Cannot convert quantity"},
		{"-1", 0, "Cannot assign negative"},
	}
	for _, test := range tests {
		q := resource.MustParse(test.qStr)
		actVal, err := QuantityToUint64(q)
		if test.expErr == "" {
			require.Nil(t, err)
			require.Equal(t, test.expVal, actVal)
		} else {
			require.NotNil(t, err)
			require.Contains(t, err.Error(), test.expErr)
		}
	}
}

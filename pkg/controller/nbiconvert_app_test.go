// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"fmt"
	"testing"

	"github.com/edgexr/edge-cloud-platform/test/nbitest"
	"github.com/test-go/testify/require"
)

func TestConvertApp(t *testing.T) {
	pairs := nbitest.AppData()

	for idx, pair := range pairs {
		desc := fmt.Sprintf("pair[%d]", idx)
		// convert NBI to App
		outProto, err := ProtoApp(pair.NBI)
		require.Nil(t, err, desc)
		require.Equal(t, pair.Edgeproto, outProto, desc)

		outNBI, err := NBIApp(pair.Edgeproto)
		require.Nil(t, err, desc)
		require.Equal(t, pair.NBI, outNBI, desc)
	}
}

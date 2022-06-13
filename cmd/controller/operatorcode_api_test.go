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
	"testing"

	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestOperatorCodeApi(t *testing.T) {
	ctx, testSvcs, apis := testinit(t)
	defer testfinish(testSvcs)

	testutil.InternalOperatorCodeTest(t, "cud", apis.operatorCodeApi, testutil.OperatorCodeData)
	// create duplicate key should fail
	code := testutil.OperatorCodeData[0]
	_, err := apis.operatorCodeApi.CreateOperatorCode(ctx, &code)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "already exists")

	// check not found error on delete
	_, err = apis.operatorCodeApi.DeleteOperatorCode(ctx, &code)
	require.Nil(t, err)
	_, err = apis.operatorCodeApi.DeleteOperatorCode(ctx, &code)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not found")
}

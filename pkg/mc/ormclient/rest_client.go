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

package ormclient

import (
	"fmt"
	"reflect"

	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/ormctl"
	"github.com/edgexr/edge-cloud-platform/pkg/restclient"
)

const TokenTypeBearer = "Bearer"

type Client struct {
	restclient.Client
}

func (s *Client) Run(apiCmd *ormctl.ApiCommand, runData *mctestclient.RunData) {
	var status int
	var err error
	uri := runData.Uri + apiCmd.Path

	if structMap, ok := runData.In.(*cli.MapData); ok && structMap != nil {
		// Passed in generic map can be in any namespace,
		// but embedded objects must not have been squashed,
		// which is what json does. So it's recommended to
		// avoid Json namespaces unless they are generated
		// from objects without marshaling.
		// The embedded hierarchy must be present, because the same
		// map data gets passed to cliwrapper and ormclient clients
		// in mctestclient generated funcs for Update/Show.
		if s.Client.PrintTransformations {
			fmt.Printf("%s: transforming map (%s) %#v to map (JsonNamespace)\n", log.GetLineno(0), structMap.Namespace.String(), runData.In)
		}
		jsonMap, err := cli.JsonMap(structMap, apiCmd.ReqData)
		if err != nil {
			runData.RetStatus = 0
			runData.RetError = err
			return
		}
		if s.Client.PrintTransformations {
			fmt.Printf("%s: transformed to map (JsonNamespace) %#v\n", log.GetLineno(0), jsonMap.Data)
		}
		runData.In = jsonMap.Data
	}

	if apiCmd.StreamOut {
		// ReplyData should be a pointer to a single object,
		// but runData.Out should be a slice of those objects.
		// Allocate a new object to store the streamed back data,
		// and then add that to the list passed in by the caller.
		objType := reflect.TypeOf(apiCmd.ReplyData)
		if objType.Kind() == reflect.Ptr {
			objType = objType.Elem()
		}
		buf := reflect.New(objType) // pointer to zero'd object

		arrV := reflect.ValueOf(runData.Out)
		if arrV.Kind() == reflect.Ptr {
			arrV = arrV.Elem()
		}
		status, err = s.Client.PostJsonStreamOut(uri, runData.Token, runData.In, buf.Interface(), runData.QueryParams, func() {
			arrV.Set(reflect.Append(arrV, reflect.Indirect(buf)))
		})
	} else {
		status, err = s.Client.PostJson(uri, runData.Token, runData.In, runData.Out, runData.QueryParams)
	}
	runData.RetStatus = status
	runData.RetError = err
}

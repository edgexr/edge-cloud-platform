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

package controller

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

// Nodes are not stored in the etcd database, because they
// are dynamic. DMEs will be instantiated as load requires on Cloudlets.
// Instead, connected DMEs are tracked independently by each controller.
// To get a list of all DMEs, we query each controller and get each
// one's list of connected DMEs/CRMs.

type SvcNodeApi struct{}

var svcNodeApi = SvcNodeApi{}

func (s *SvcNodeApi) ShowSvcNode(in *edgeproto.SvcNode, cb edgeproto.SvcNodeApi_ShowSvcNodeServer) error {
	if *notifyRootAddrs == "" && *notifyParentAddrs == "" {
		// assume this is the root
		return nodeMgr.SvcNodeCache.Show(in, func(obj *edgeproto.SvcNode) error {
			err := cb.Send(obj)
			return err
		})
	}

	// ShowNode should directly communicate with NotifyRoot and not via MC
	notifyAddrs := *notifyRootAddrs
	if notifyAddrs == "" {
		// In case notifyrootaddrs is not specified,
		// fallback to notifyparentaddrs
		notifyAddrs = *notifyParentAddrs
	}

	conn, err := notifyRootConnect(cb.Context(), notifyAddrs)
	if err != nil {
		return err
	}
	client := edgeproto.NewSvcNodeApiClient(conn)
	ctx, cancel := context.WithTimeout(cb.Context(), 3*time.Second)
	defer cancel()

	stream, err := client.ShowSvcNode(ctx, in)
	if err != nil {
		return err
	}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("ShowSvcNode failed, %v", err)
		}
		err = cb.Send(obj)
		if err != nil {
			return err
		}
	}
	return nil
}

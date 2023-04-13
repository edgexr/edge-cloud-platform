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

package dmetest

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

// AppInstClients - test the Clients
var AppInstClientData = []edgeproto.AppInstClient{
	{
		ClientKey: edgeproto.AppInstClientKey{
			AppInstKey: edgeproto.AppInstKey{
				Name:         "appInst1",
				Organization: "devorg1",
				CloudletKey: edgeproto.CloudletKey{
					Name:         "cloudlet1",
					Organization: "operator1",
				},
			},
			AppKey: edgeproto.AppKey{
				Name:         "app1",
				Organization: "devorg1",
				Version:      "1.0",
			},
			UniqueId:     "1",
			UniqueIdType: "testuuid",
		},
	},
	{
		ClientKey: edgeproto.AppInstClientKey{
			AppInstKey: edgeproto.AppInstKey{
				Name:         "appInst2",
				Organization: "devorg2",
				CloudletKey: edgeproto.CloudletKey{
					Name:         "cloudlet1",
					Organization: "operator1",
				},
			},
			AppKey: edgeproto.AppKey{
				Name:         "app2",
				Organization: "devorg2",
				Version:      "1.0",
			},
			UniqueId:     "2",
			UniqueIdType: "testuuid",
		},
	},
	// Same as AppInstClientData[0], but on a different cloudlet
	{
		ClientKey: edgeproto.AppInstClientKey{
			AppInstKey: edgeproto.AppInstKey{
				Name:         "appInst1",
				Organization: "devorg1",
				CloudletKey: edgeproto.CloudletKey{
					Name:         "cloudlet2",
					Organization: "operator2",
				},
			},
			AppKey: edgeproto.AppKey{
				Name:         "app1",
				Organization: "devorg1",
				Version:      "1.0",
			},
			UniqueId:     "1",
			UniqueIdType: "testuuid",
		},
	},
	{
		ClientKey: edgeproto.AppInstClientKey{
			AppInstKey: edgeproto.AppInstKey{
				Name:         "appInst1",
				Organization: "devorg1",
				CloudletKey: edgeproto.CloudletKey{
					Name:         "cloudlet1",
					Organization: "operator1",
				},
			},
			AppKey: edgeproto.AppKey{
				Name:         "app1",
				Organization: "devorg1",
				Version:      "1.0",
			},
			UniqueId:     "3",
			UniqueIdType: "testuuid",
		},
	},
	{
		ClientKey: edgeproto.AppInstClientKey{
			AppInstKey: edgeproto.AppInstKey{
				Name:         "appInst1",
				Organization: "devorg1",
				CloudletKey: edgeproto.CloudletKey{
					Name:         "cloudlet1",
					Organization: "operator1",
				},
			},
			AppKey: edgeproto.AppKey{
				Name:         "app1",
				Organization: "devorg1",
				Version:      "1.0",
			},
			UniqueId:     "4",
			UniqueIdType: "testuuid",
		},
	},
}

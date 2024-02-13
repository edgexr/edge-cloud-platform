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

package cloudcommon

import (
	"fmt"

	"github.com/golang/protobuf/proto"
)

// Implements grpc.Codec to allow the more recent versions of
// grpc to use the gogo protobuf marshaling functions.
type ProtoCodec struct{}

func (s *ProtoCodec) Marshal(v interface{}) ([]byte, error) {
	if pm, ok := v.(proto.Marshaler); ok {
		// gogo marshaling
		return pm.Marshal()
	}
	if vv, ok := v.(proto.Message); ok {
		// current grpc marshaling using reflect
		return proto.Marshal(vv)
	}
	return nil, fmt.Errorf("object does not implement proto.Marshaler or proto.Message")
}

func (s *ProtoCodec) Unmarshal(data []byte, v interface{}) error {
	if pu, ok := v.(proto.Unmarshaler); ok {
		// gogo marshaling
		return pu.Unmarshal(data)
	}
	if vv, ok := v.(proto.Message); ok {
		// current grpc marshaling using reflect
		return proto.Unmarshal(data, vv)
	}
	return fmt.Errorf("object does not implement proto.Unmarshaler or proto.Message")
}

func (s *ProtoCodec) Name() string {
	return "proto"
}

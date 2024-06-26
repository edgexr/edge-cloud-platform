// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: stream.proto

package edgeproto

import (
	context "context"
	"encoding/json"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
	reflect "reflect"
	"strconv"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Stream State
//
// Indicates if stream has started/ended or in a bad shape
//
// 0: `STREAM_UNKNOWN`
// 1: `STREAM_START`
// 2: `STREAM_STOP`
// 3: `STREAM_ERROR`
type StreamState int32

const (
	// Stream state is unknown
	StreamState_STREAM_UNKNOWN StreamState = 0
	// Stream has started
	StreamState_STREAM_START StreamState = 1
	// Stream has stopped
	StreamState_STREAM_STOP StreamState = 2
	// Stream is in error state
	StreamState_STREAM_ERROR StreamState = 3
)

var StreamState_name = map[int32]string{
	0: "STREAM_UNKNOWN",
	1: "STREAM_START",
	2: "STREAM_STOP",
	3: "STREAM_ERROR",
}

var StreamState_value = map[string]int32{
	"STREAM_UNKNOWN": 0,
	"STREAM_START":   1,
	"STREAM_STOP":    2,
	"STREAM_ERROR":   3,
}

func (x StreamState) String() string {
	return proto.EnumName(StreamState_name, int32(x))
}

func (StreamState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_bb17ef3f514bfe54, []int{0}
}

func init() {
	proto.RegisterEnum("edgeproto.StreamState", StreamState_name, StreamState_value)
}

func init() { proto.RegisterFile("stream.proto", fileDescriptor_bb17ef3f514bfe54) }

var fileDescriptor_bb17ef3f514bfe54 = []byte{
	// 487 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0x3f, 0x6f, 0xd3, 0x40,
	0x14, 0xc0, 0x7d, 0x05, 0x21, 0x71, 0x4d, 0x13, 0xe7, 0x68, 0x8b, 0x89, 0x8a, 0x07, 0x4f, 0x50,
	0x55, 0x31, 0x7f, 0x06, 0x24, 0x36, 0x03, 0x15, 0x82, 0x40, 0x5c, 0x39, 0x49, 0x99, 0x10, 0x72,
	0x93, 0x27, 0xcb, 0x60, 0x7c, 0xd6, 0xdd, 0x19, 0x14, 0x46, 0x16, 0x06, 0x16, 0x24, 0x24, 0x3e,
	0x00, 0x13, 0x1f, 0xa5, 0x63, 0x25, 0x16, 0x46, 0x48, 0x3a, 0x65, 0x0e, 0x3b, 0xea, 0xdd, 0xd9,
	0x75, 0x50, 0xa3, 0x6e, 0xef, 0x7e, 0xef, 0xd9, 0xef, 0xf7, 0xde, 0x1d, 0xae, 0x71, 0xc1, 0x20,
	0x7c, 0xdb, 0xce, 0x18, 0x15, 0x94, 0x5c, 0x86, 0x51, 0x04, 0x32, 0x6c, 0xd5, 0x18, 0xf0, 0x3c,
	0x11, 0x2a, 0xd1, 0x5a, 0x0b, 0xb3, 0x2c, 0x4e, 0x79, 0x71, 0x6c, 0x0e, 0x93, 0x9c, 0x0b, 0x60,
	0x8b, 0x88, 0xe6, 0xa3, 0x04, 0xc4, 0x1b, 0x18, 0x6b, 0x54, 0x2f, 0x90, 0x3e, 0x5f, 0x17, 0x94,
	0x26, 0xdc, 0x95, 0x87, 0x08, 0xd2, 0x32, 0xd0, 0xe9, 0xad, 0x88, 0xd2, 0x28, 0x01, 0x37, 0xcc,
	0x62, 0x37, 0x4c, 0x53, 0x2a, 0x42, 0x11, 0xd3, 0x94, 0xeb, 0xec, 0x7a, 0x44, 0x23, 0x2a, 0x43,
	0xf7, 0x24, 0x52, 0x74, 0x7b, 0x1f, 0xaf, 0xf6, 0xe4, 0x00, 0x3d, 0x11, 0x0a, 0x20, 0x04, 0xd7,
	0x7b, 0xfd, 0x60, 0xd7, 0x7b, 0xfe, 0x6a, 0xd0, 0xed, 0x74, 0xfd, 0x17, 0x5d, 0xd3, 0x20, 0x26,
	0xae, 0x69, 0xd6, 0xeb, 0x7b, 0x41, 0xdf, 0x44, 0xa4, 0x81, 0x57, 0x4b, 0xe2, 0xef, 0x99, 0x2b,
	0x95, 0x92, 0xdd, 0x20, 0xf0, 0x03, 0xf3, 0xc2, 0x9d, 0xe3, 0x8b, 0xb8, 0xa6, 0x7e, 0xec, 0x1f,
	0xbc, 0xf6, 0xb2, 0x98, 0x7c, 0x42, 0x78, 0x4d, 0x01, 0x2f, 0xcb, 0x9e, 0xa4, 0x5c, 0x90, 0x8d,
	0x76, 0xb9, 0xac, 0xb6, 0x66, 0x1d, 0x18, 0xb7, 0x9a, 0x15, 0x1c, 0xc8, 0x15, 0x3a, 0x4f, 0x67,
	0x73, 0xeb, 0x46, 0x00, 0x9c, 0xe6, 0x6c, 0x08, 0xba, 0x94, 0xef, 0x78, 0xc3, 0x93, 0xf1, 0xf6,
	0x63, 0x78, 0xbf, 0xe3, 0xb3, 0x28, 0x4c, 0xe3, 0x0f, 0x72, 0xde, 0x1f, 0x7f, 0x2d, 0xf4, 0xf1,
	0xe7, 0xf1, 0xd7, 0x95, 0x75, 0xa7, 0xe1, 0xaa, 0xcb, 0x71, 0xf5, 0xf2, 0xef, 0xa3, 0xed, 0x5b,
	0x88, 0x7c, 0x47, 0xb8, 0xa9, 0x4c, 0x1e, 0xaa, 0x4b, 0x90, 0x36, 0xd7, 0x2a, 0x6d, 0x2b, 0x7c,
	0x89, 0xd1, 0xcb, 0xd9, 0xdc, 0xba, 0x57, 0x18, 0x55, 0xca, 0x17, 0xac, 0x34, 0xef, 0xc0, 0xb8,
	0x7d, 0xa6, 0xa0, 0xe5, 0x5c, 0x29, 0x04, 0x2b, 0xcf, 0x41, 0x49, 0x7e, 0x46, 0xb8, 0x5e, 0x48,
	0xaa, 0x37, 0x40, 0x36, 0x17, 0x0c, 0x15, 0x5c, 0xa2, 0xf7, 0x6c, 0x36, 0xb7, 0x6e, 0x9e, 0xea,
	0xa9, 0xda, 0xf3, 0x37, 0xb6, 0xe1, 0x98, 0xa7, 0x42, 0xea, 0x23, 0x65, 0xf3, 0x0d, 0xe1, 0x86,
	0xb2, 0x79, 0xbc, 0x37, 0x78, 0xc4, 0xe2, 0x77, 0xc0, 0xc8, 0xd5, 0x4a, 0xdb, 0x92, 0x2e, 0xf1,
	0x19, 0xcc, 0xe6, 0xd6, 0xed, 0xff, 0x7d, 0xbc, 0x34, 0x4c, 0xc6, 0x22, 0x1e, 0x9e, 0xef, 0xb5,
	0xe9, 0x34, 0x0b, 0xaf, 0x28, 0xcb, 0x47, 0xb2, 0x93, 0x14, 0x7b, 0xb0, 0x75, 0xf8, 0xc7, 0x36,
	0x0e, 0x27, 0x36, 0x3a, 0x9a, 0xd8, 0xe8, 0xf7, 0xc4, 0x46, 0x5f, 0xa6, 0xb6, 0x71, 0x34, 0xb5,
	0x8d, 0x5f, 0x53, 0xdb, 0x38, 0xb8, 0x24, 0x25, 0xee, 0xfe, 0x0b, 0x00, 0x00, 0xff, 0xff, 0x99,
	0x58, 0x15, 0x60, 0xa4, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// StreamObjApiClient is the client API for StreamObjApi service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type StreamObjApiClient interface {
	// Stream Application Instance current progress
	StreamAppInst(ctx context.Context, in *AppInstKey, opts ...grpc.CallOption) (StreamObjApi_StreamAppInstClient, error)
	// Stream Cluster Instance current progress
	StreamClusterInst(ctx context.Context, in *ClusterInstKey, opts ...grpc.CallOption) (StreamObjApi_StreamClusterInstClient, error)
	// Stream Cloudlet current progress
	StreamCloudlet(ctx context.Context, in *CloudletKey, opts ...grpc.CallOption) (StreamObjApi_StreamCloudletClient, error)
	// Stream GPU driver current progress
	StreamGPUDriver(ctx context.Context, in *GPUDriverKey, opts ...grpc.CallOption) (StreamObjApi_StreamGPUDriverClient, error)
}

type streamObjApiClient struct {
	cc *grpc.ClientConn
}

func NewStreamObjApiClient(cc *grpc.ClientConn) StreamObjApiClient {
	return &streamObjApiClient{cc}
}

func (c *streamObjApiClient) StreamAppInst(ctx context.Context, in *AppInstKey, opts ...grpc.CallOption) (StreamObjApi_StreamAppInstClient, error) {
	stream, err := c.cc.NewStream(ctx, &_StreamObjApi_serviceDesc.Streams[0], "/edgeproto.StreamObjApi/StreamAppInst", opts...)
	if err != nil {
		return nil, err
	}
	x := &streamObjApiStreamAppInstClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type StreamObjApi_StreamAppInstClient interface {
	Recv() (*Result, error)
	grpc.ClientStream
}

type streamObjApiStreamAppInstClient struct {
	grpc.ClientStream
}

func (x *streamObjApiStreamAppInstClient) Recv() (*Result, error) {
	m := new(Result)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *streamObjApiClient) StreamClusterInst(ctx context.Context, in *ClusterInstKey, opts ...grpc.CallOption) (StreamObjApi_StreamClusterInstClient, error) {
	stream, err := c.cc.NewStream(ctx, &_StreamObjApi_serviceDesc.Streams[1], "/edgeproto.StreamObjApi/StreamClusterInst", opts...)
	if err != nil {
		return nil, err
	}
	x := &streamObjApiStreamClusterInstClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type StreamObjApi_StreamClusterInstClient interface {
	Recv() (*Result, error)
	grpc.ClientStream
}

type streamObjApiStreamClusterInstClient struct {
	grpc.ClientStream
}

func (x *streamObjApiStreamClusterInstClient) Recv() (*Result, error) {
	m := new(Result)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *streamObjApiClient) StreamCloudlet(ctx context.Context, in *CloudletKey, opts ...grpc.CallOption) (StreamObjApi_StreamCloudletClient, error) {
	stream, err := c.cc.NewStream(ctx, &_StreamObjApi_serviceDesc.Streams[2], "/edgeproto.StreamObjApi/StreamCloudlet", opts...)
	if err != nil {
		return nil, err
	}
	x := &streamObjApiStreamCloudletClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type StreamObjApi_StreamCloudletClient interface {
	Recv() (*Result, error)
	grpc.ClientStream
}

type streamObjApiStreamCloudletClient struct {
	grpc.ClientStream
}

func (x *streamObjApiStreamCloudletClient) Recv() (*Result, error) {
	m := new(Result)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *streamObjApiClient) StreamGPUDriver(ctx context.Context, in *GPUDriverKey, opts ...grpc.CallOption) (StreamObjApi_StreamGPUDriverClient, error) {
	stream, err := c.cc.NewStream(ctx, &_StreamObjApi_serviceDesc.Streams[3], "/edgeproto.StreamObjApi/StreamGPUDriver", opts...)
	if err != nil {
		return nil, err
	}
	x := &streamObjApiStreamGPUDriverClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type StreamObjApi_StreamGPUDriverClient interface {
	Recv() (*Result, error)
	grpc.ClientStream
}

type streamObjApiStreamGPUDriverClient struct {
	grpc.ClientStream
}

func (x *streamObjApiStreamGPUDriverClient) Recv() (*Result, error) {
	m := new(Result)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// StreamObjApiServer is the server API for StreamObjApi service.
type StreamObjApiServer interface {
	// Stream Application Instance current progress
	StreamAppInst(*AppInstKey, StreamObjApi_StreamAppInstServer) error
	// Stream Cluster Instance current progress
	StreamClusterInst(*ClusterInstKey, StreamObjApi_StreamClusterInstServer) error
	// Stream Cloudlet current progress
	StreamCloudlet(*CloudletKey, StreamObjApi_StreamCloudletServer) error
	// Stream GPU driver current progress
	StreamGPUDriver(*GPUDriverKey, StreamObjApi_StreamGPUDriverServer) error
}

// UnimplementedStreamObjApiServer can be embedded to have forward compatible implementations.
type UnimplementedStreamObjApiServer struct {
}

func (*UnimplementedStreamObjApiServer) StreamAppInst(req *AppInstKey, srv StreamObjApi_StreamAppInstServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamAppInst not implemented")
}
func (*UnimplementedStreamObjApiServer) StreamClusterInst(req *ClusterInstKey, srv StreamObjApi_StreamClusterInstServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamClusterInst not implemented")
}
func (*UnimplementedStreamObjApiServer) StreamCloudlet(req *CloudletKey, srv StreamObjApi_StreamCloudletServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamCloudlet not implemented")
}
func (*UnimplementedStreamObjApiServer) StreamGPUDriver(req *GPUDriverKey, srv StreamObjApi_StreamGPUDriverServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamGPUDriver not implemented")
}

func RegisterStreamObjApiServer(s *grpc.Server, srv StreamObjApiServer) {
	s.RegisterService(&_StreamObjApi_serviceDesc, srv)
}

func _StreamObjApi_StreamAppInst_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(AppInstKey)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(StreamObjApiServer).StreamAppInst(m, &streamObjApiStreamAppInstServer{stream})
}

type StreamObjApi_StreamAppInstServer interface {
	Send(*Result) error
	grpc.ServerStream
}

type streamObjApiStreamAppInstServer struct {
	grpc.ServerStream
}

func (x *streamObjApiStreamAppInstServer) Send(m *Result) error {
	return x.ServerStream.SendMsg(m)
}

func _StreamObjApi_StreamClusterInst_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ClusterInstKey)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(StreamObjApiServer).StreamClusterInst(m, &streamObjApiStreamClusterInstServer{stream})
}

type StreamObjApi_StreamClusterInstServer interface {
	Send(*Result) error
	grpc.ServerStream
}

type streamObjApiStreamClusterInstServer struct {
	grpc.ServerStream
}

func (x *streamObjApiStreamClusterInstServer) Send(m *Result) error {
	return x.ServerStream.SendMsg(m)
}

func _StreamObjApi_StreamCloudlet_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(CloudletKey)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(StreamObjApiServer).StreamCloudlet(m, &streamObjApiStreamCloudletServer{stream})
}

type StreamObjApi_StreamCloudletServer interface {
	Send(*Result) error
	grpc.ServerStream
}

type streamObjApiStreamCloudletServer struct {
	grpc.ServerStream
}

func (x *streamObjApiStreamCloudletServer) Send(m *Result) error {
	return x.ServerStream.SendMsg(m)
}

func _StreamObjApi_StreamGPUDriver_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GPUDriverKey)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(StreamObjApiServer).StreamGPUDriver(m, &streamObjApiStreamGPUDriverServer{stream})
}

type StreamObjApi_StreamGPUDriverServer interface {
	Send(*Result) error
	grpc.ServerStream
}

type streamObjApiStreamGPUDriverServer struct {
	grpc.ServerStream
}

func (x *streamObjApiStreamGPUDriverServer) Send(m *Result) error {
	return x.ServerStream.SendMsg(m)
}

var _StreamObjApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.StreamObjApi",
	HandlerType: (*StreamObjApiServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamAppInst",
			Handler:       _StreamObjApi_StreamAppInst_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "StreamClusterInst",
			Handler:       _StreamObjApi_StreamClusterInst_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "StreamCloudlet",
			Handler:       _StreamObjApi_StreamCloudlet_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "StreamGPUDriver",
			Handler:       _StreamObjApi_StreamGPUDriver_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "stream.proto",
}

var StreamStateStrings = []string{
	"STREAM_UNKNOWN",
	"STREAM_START",
	"STREAM_STOP",
	"STREAM_ERROR",
}

const (
	StreamStateSTREAM_UNKNOWN uint64 = 1 << 0
	StreamStateSTREAM_START   uint64 = 1 << 1
	StreamStateSTREAM_STOP    uint64 = 1 << 2
	StreamStateSTREAM_ERROR   uint64 = 1 << 3
)

var StreamState_CamelName = map[int32]string{
	// STREAM_UNKNOWN -> StreamUnknown
	0: "StreamUnknown",
	// STREAM_START -> StreamStart
	1: "StreamStart",
	// STREAM_STOP -> StreamStop
	2: "StreamStop",
	// STREAM_ERROR -> StreamError
	3: "StreamError",
}
var StreamState_CamelValue = map[string]int32{
	"StreamUnknown": 0,
	"StreamStart":   1,
	"StreamStop":    2,
	"StreamError":   3,
}

func ParseStreamState(data interface{}) (StreamState, error) {
	if val, ok := data.(StreamState); ok {
		return val, nil
	} else if str, ok := data.(string); ok {
		val, ok := StreamState_CamelValue[util.CamelCase(str)]
		if !ok {
			// may have omitted common prefix
			val, ok = StreamState_CamelValue["Stream"+util.CamelCase(str)]
		}
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = StreamState_CamelName[val]
			}
		}
		if !ok {
			return StreamState(0), fmt.Errorf("Invalid StreamState value %q", str)
		}
		return StreamState(val), nil
	} else if ival, ok := data.(int32); ok {
		if _, ok := StreamState_CamelName[ival]; ok {
			return StreamState(ival), nil
		} else {
			return StreamState(0), fmt.Errorf("Invalid StreamState value %d", ival)
		}
	}
	return StreamState(0), fmt.Errorf("Invalid StreamState value %v", data)
}

func (e *StreamState) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, err := ParseStreamState(str)
	if err != nil {
		return err
	}
	*e = val
	return nil
}

func (e StreamState) MarshalYAML() (interface{}, error) {
	str := proto.EnumName(StreamState_CamelName, int32(e))
	str = strings.TrimPrefix(str, "Stream")
	return str, nil
}

// custom JSON encoding/decoding
func (e *StreamState) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, err := ParseStreamState(str)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: "string " + str,
				Type:  reflect.TypeOf(StreamState(0)),
			}
		}
		*e = StreamState(val)
		return nil
	}
	var ival int32
	err = json.Unmarshal(b, &ival)
	if err == nil {
		val, err := ParseStreamState(ival)
		if err == nil {
			*e = val
			return nil
		}
	}
	return &json.UnmarshalTypeError{
		Value: "value " + string(b),
		Type:  reflect.TypeOf(StreamState(0)),
	}
}

func (e StreamState) MarshalJSON() ([]byte, error) {
	str := proto.EnumName(StreamState_CamelName, int32(e))
	str = strings.TrimPrefix(str, "Stream")
	return json.Marshal(str)
}

var StreamStateCommonPrefix = "Stream"

func (m *AppInstKey) IsValidArgsForStreamAppInst() error {
	return nil
}

func (m *ClusterInstKey) IsValidArgsForStreamClusterInst() error {
	return nil
}

func (m *CloudletKey) IsValidArgsForStreamCloudlet() error {
	return nil
}

func (m *GPUDriverKey) IsValidArgsForStreamGPUDriver() error {
	return nil
}

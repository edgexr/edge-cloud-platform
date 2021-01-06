// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: stream.proto

package edgeproto

import (
	context "context"
	"encoding/json"
	"errors"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	"github.com/mobiledgex/edge-cloud/util"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
	"strconv"
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
	// 469 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x92, 0x41, 0x6f, 0xd3, 0x30,
	0x18, 0x86, 0xe3, 0x81, 0x90, 0xf0, 0xba, 0x36, 0x35, 0x1b, 0x0a, 0xd5, 0x94, 0x43, 0x6f, 0x4c,
	0x25, 0x9e, 0xe0, 0x82, 0xb8, 0xa0, 0x80, 0x76, 0x40, 0xdd, 0x1a, 0x48, 0xcb, 0x38, 0x22, 0x37,
	0xb3, 0x8c, 0x51, 0x1a, 0x5b, 0xb1, 0x23, 0x18, 0x47, 0x4e, 0x48, 0x48, 0x08, 0x89, 0x03, 0x7f,
	0x81, 0x9f, 0xb2, 0xe3, 0x24, 0x2e, 0x1c, 0xa1, 0xe5, 0xd4, 0x73, 0xb9, 0xa3, 0xda, 0x49, 0x97,
	0x49, 0x4c, 0x68, 0x97, 0xe8, 0xf3, 0xe3, 0xd7, 0xce, 0x63, 0x7f, 0x86, 0x0d, 0xa5, 0x73, 0x4a,
	0x26, 0x81, 0xcc, 0x85, 0x16, 0xe8, 0x3a, 0x3d, 0x62, 0xd4, 0x94, 0x9d, 0x46, 0x4e, 0x55, 0x91,
	0x6a, 0x3b, 0xd1, 0xd9, 0x20, 0x52, 0xf2, 0x4c, 0x55, 0xc3, 0x76, 0x92, 0x16, 0x4a, 0xd3, 0xbc,
	0x86, 0x9a, 0x49, 0x2a, 0x8a, 0xa3, 0x94, 0x56, 0xe3, 0xfb, 0x8c, 0xeb, 0x57, 0xc5, 0x38, 0x48,
	0xc4, 0x04, 0x4f, 0xc4, 0x98, 0xa7, 0xcb, 0xad, 0xdf, 0xe2, 0xe5, 0xf7, 0x8e, 0x89, 0x62, 0x93,
	0x63, 0x34, 0x5b, 0x15, 0xe5, 0xca, 0x6d, 0x26, 0x04, 0x4b, 0x29, 0x26, 0x92, 0x63, 0x92, 0x65,
	0x42, 0x13, 0xcd, 0x45, 0xa6, 0xca, 0xd9, 0x4d, 0x26, 0x98, 0x30, 0x25, 0x5e, 0x56, 0x96, 0xee,
	0x1c, 0xc2, 0xf5, 0xa1, 0x39, 0xc8, 0x50, 0x13, 0x4d, 0x11, 0x82, 0xcd, 0xe1, 0x28, 0xde, 0x0b,
	0x0f, 0x5e, 0x3e, 0x1f, 0xf4, 0x07, 0xd1, 0x8b, 0x81, 0xeb, 0x20, 0x17, 0x36, 0x4a, 0x36, 0x1c,
	0x85, 0xf1, 0xc8, 0x05, 0xa8, 0x05, 0xd7, 0x57, 0x24, 0x7a, 0xea, 0xae, 0xd5, 0x22, 0x7b, 0x71,
	0x1c, 0xc5, 0xee, 0x95, 0xbb, 0x1f, 0xae, 0xc2, 0x86, 0xdd, 0x38, 0x1a, 0xbf, 0x0e, 0x25, 0x47,
	0x9f, 0x00, 0xdc, 0xb0, 0x20, 0x94, 0xf2, 0x49, 0xa6, 0x34, 0xda, 0x0a, 0x56, 0x97, 0x16, 0x94,
	0xac, 0x4f, 0x8f, 0x3b, 0xed, 0x1a, 0x8e, 0xcd, 0x55, 0x76, 0x9f, 0xcd, 0x17, 0x1e, 0x8e, 0xa9,
	0x12, 0x45, 0x9e, 0xd0, 0x32, 0xaa, 0x7a, 0x61, 0xb2, 0x3c, 0xde, 0x21, 0xa7, 0x6f, 0x7a, 0xa1,
	0x94, 0x7d, 0x7a, 0x1c, 0x44, 0x39, 0x23, 0x19, 0x7f, 0x67, 0x8e, 0xfd, 0xed, 0x8f, 0x07, 0xde,
	0x7f, 0xff, 0xfd, 0x65, 0x6d, 0xb3, 0xdb, 0xc2, 0xb6, 0x57, 0xb8, 0xec, 0xc5, 0x03, 0xb0, 0xb3,
	0x0b, 0xd0, 0x57, 0x00, 0xdb, 0x56, 0xe8, 0xb1, 0xed, 0x89, 0x91, 0xba, 0x55, 0xfb, 0x7b, 0x8d,
	0x5f, 0x20, 0x16, 0xcf, 0x17, 0x5e, 0xaf, 0x12, 0xab, 0xc5, 0xcf, 0xc9, 0xfd, 0xd3, 0xca, 0xeb,
	0xde, 0xa8, 0xac, 0x6a, 0x4f, 0xc2, 0x9a, 0x7d, 0x04, 0xb0, 0x59, 0x99, 0xd9, 0xa7, 0x81, 0x6e,
	0x9e, 0xd3, 0xb2, 0xf0, 0x02, 0xa7, 0xfd, 0xf9, 0xc2, 0xbb, 0x7d, 0xe6, 0x64, 0xb3, 0xff, 0x17,
	0xda, 0xea, 0xba, 0x67, 0x42, 0x76, 0x91, 0xb5, 0x79, 0x08, 0x5b, 0x56, 0x66, 0x5f, 0x24, 0x24,
	0x3d, 0x50, 0x4c, 0x5d, 0xa2, 0x73, 0xce, 0x2e, 0x78, 0xb4, 0x7d, 0xf2, 0xcb, 0x77, 0x4e, 0xa6,
	0x3e, 0x38, 0x9d, 0xfa, 0xe0, 0xe7, 0xd4, 0x07, 0x9f, 0x67, 0xbe, 0x73, 0x3a, 0xf3, 0x9d, 0x1f,
	0x33, 0xdf, 0x19, 0x5f, 0x33, 0xf9, 0x7b, 0x7f, 0x03, 0x00, 0x00, 0xff, 0xff, 0xce, 0x64, 0x21,
	0xd6, 0x50, 0x03, 0x00, 0x00,
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
	// This is used internally to forward requests to other Controllers
	StreamLocalMsgs(ctx context.Context, in *AppInstKey, opts ...grpc.CallOption) (StreamObjApi_StreamLocalMsgsClient, error)
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

func (c *streamObjApiClient) StreamLocalMsgs(ctx context.Context, in *AppInstKey, opts ...grpc.CallOption) (StreamObjApi_StreamLocalMsgsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_StreamObjApi_serviceDesc.Streams[3], "/edgeproto.StreamObjApi/StreamLocalMsgs", opts...)
	if err != nil {
		return nil, err
	}
	x := &streamObjApiStreamLocalMsgsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type StreamObjApi_StreamLocalMsgsClient interface {
	Recv() (*Result, error)
	grpc.ClientStream
}

type streamObjApiStreamLocalMsgsClient struct {
	grpc.ClientStream
}

func (x *streamObjApiStreamLocalMsgsClient) Recv() (*Result, error) {
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
	// This is used internally to forward requests to other Controllers
	StreamLocalMsgs(*AppInstKey, StreamObjApi_StreamLocalMsgsServer) error
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
func (*UnimplementedStreamObjApiServer) StreamLocalMsgs(req *AppInstKey, srv StreamObjApi_StreamLocalMsgsServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamLocalMsgs not implemented")
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

func _StreamObjApi_StreamLocalMsgs_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(AppInstKey)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(StreamObjApiServer).StreamLocalMsgs(m, &streamObjApiStreamLocalMsgsServer{stream})
}

type StreamObjApi_StreamLocalMsgsServer interface {
	Send(*Result) error
	grpc.ServerStream
}

type streamObjApiStreamLocalMsgsServer struct {
	grpc.ServerStream
}

func (x *streamObjApiStreamLocalMsgsServer) Send(m *Result) error {
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
			StreamName:    "StreamLocalMsgs",
			Handler:       _StreamObjApi_StreamLocalMsgs_Handler,
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

func (e *StreamState) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, ok := StreamState_CamelValue[util.CamelCase(str)]
	if !ok {
		// may be enum value instead of string
		ival, err := strconv.Atoi(str)
		val = int32(ival)
		if err == nil {
			_, ok = StreamState_CamelName[val]
		}
	}
	if !ok {
		return errors.New(fmt.Sprintf("No enum value for %s", str))
	}
	*e = StreamState(val)
	return nil
}

func (e StreamState) MarshalYAML() (interface{}, error) {
	return proto.EnumName(StreamState_CamelName, int32(e)), nil
}

// custom JSON encoding/decoding
func (e *StreamState) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, ok := StreamState_CamelValue[util.CamelCase(str)]
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = StreamState_CamelName[val]
			}
		}
		if !ok {
			return errors.New(fmt.Sprintf("No enum value for %s", str))
		}
		*e = StreamState(val)
		return nil
	}
	var val int32
	err = json.Unmarshal(b, &val)
	if err == nil {
		*e = StreamState(val)
		return nil
	}
	return fmt.Errorf("No enum value for %v", b)
}
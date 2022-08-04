// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudletaccess.proto

package testutil

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/edgectl/wrapper"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func (r *Run) CloudletAccessApi_AccessDataRequest(data *[]edgeproto.AccessDataRequest, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for AccessDataRequest", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "getaccessdata":
			out, err := r.client.GetAccessData(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("CloudletAccessApi_AccessDataRequest[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.AccessDataReply)
				if !ok {
					panic(fmt.Sprintf("RunCloudletAccessApi_AccessDataRequest expected dataOut type *[]edgeproto.AccessDataReply, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (r *Run) CloudletAccessApi_GetCasRequest(data *[]edgeproto.GetCasRequest, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for GetCasRequest", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "getcas":
			out, err := r.client.GetCas(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("CloudletAccessApi_GetCasRequest[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.GetCasReply)
				if !ok {
					panic(fmt.Sprintf("RunCloudletAccessApi_GetCasRequest expected dataOut type *[]edgeproto.GetCasReply, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (r *Run) CloudletAccessApi_IssueCertRequest(data *[]edgeproto.IssueCertRequest, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for IssueCertRequest", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "issuecert":
			out, err := r.client.IssueCert(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("CloudletAccessApi_IssueCertRequest[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.IssueCertReply)
				if !ok {
					panic(fmt.Sprintf("RunCloudletAccessApi_IssueCertRequest expected dataOut type *[]edgeproto.IssueCertReply, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (s *ApiClient) IssueCert(ctx context.Context, in *edgeproto.IssueCertRequest) (*edgeproto.IssueCertReply, error) {
	api := edgeproto.NewCloudletAccessApiClient(s.Conn)
	return api.IssueCert(ctx, in)
}

func (s *CliClient) IssueCert(ctx context.Context, in *edgeproto.IssueCertRequest) (*edgeproto.IssueCertReply, error) {
	out := edgeproto.IssueCertReply{}
	args := append(s.BaseArgs, "controller", "IssueCert")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) GetCas(ctx context.Context, in *edgeproto.GetCasRequest) (*edgeproto.GetCasReply, error) {
	api := edgeproto.NewCloudletAccessApiClient(s.Conn)
	return api.GetCas(ctx, in)
}

func (s *CliClient) GetCas(ctx context.Context, in *edgeproto.GetCasRequest) (*edgeproto.GetCasReply, error) {
	out := edgeproto.GetCasReply{}
	args := append(s.BaseArgs, "controller", "GetCas")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) GetAccessData(ctx context.Context, in *edgeproto.AccessDataRequest) (*edgeproto.AccessDataReply, error) {
	api := edgeproto.NewCloudletAccessApiClient(s.Conn)
	return api.GetAccessData(ctx, in)
}

func (s *CliClient) GetAccessData(ctx context.Context, in *edgeproto.AccessDataRequest) (*edgeproto.AccessDataReply, error) {
	out := edgeproto.AccessDataReply{}
	args := append(s.BaseArgs, "controller", "GetAccessData")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type CloudletAccessApiClient interface {
	IssueCert(ctx context.Context, in *edgeproto.IssueCertRequest) (*edgeproto.IssueCertReply, error)
	GetCas(ctx context.Context, in *edgeproto.GetCasRequest) (*edgeproto.GetCasReply, error)
	GetAccessData(ctx context.Context, in *edgeproto.AccessDataRequest) (*edgeproto.AccessDataReply, error)
}

package main

import (
	"context"
	"sync"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

// AppInstLabels tracks the mapping from labels put on
// infra objects to the AppInst keys that the objects belong to.
// Labels often have formatting requirements, so the values of
// the labels may not be exactly the same as the AppInst key values.
type AppInstLabels struct {
	labels    map[cloudcommon.AppInstLabels]AppInstLabelInfo
	labelsOld map[cloudcommon.AppInstLabelsOld]AppInstLabelInfo
	mux       sync.Mutex
}

type AppInstLabelInfo struct {
	AppInstKey edgeproto.AppInstKey
	AppKey     edgeproto.AppKey
}

func getAppInstLabelKeys(labels map[string]string) (cloudcommon.AppInstLabels, cloudcommon.AppInstLabelsOld) {
	labelKey := cloudcommon.AppInstLabels{}
	labelKeyOld := cloudcommon.AppInstLabelsOld{}
	labelKey.FromMap(labels)
	labelKeyOld.FromMap(labels)
	return labelKey, labelKeyOld
}

func (s *AppInstLabels) TrackAppInst(ctx context.Context, appInst *edgeproto.AppInst) {
	track := true
	s.trackAppInst(ctx, appInst, track)
}

func (s *AppInstLabels) UntrackAppInst(ctx context.Context, appInst *edgeproto.AppInst) {
	track := false
	s.trackAppInst(ctx, appInst, track)
}

func (s *AppInstLabels) trackAppInst(ctx context.Context, appInst *edgeproto.AppInst, track bool) {
	labelKey := cloudcommon.GetAppInstLabels(appInst)
	labelKeyOld := cloudcommon.GetAppInstLabelsOld(appInst)

	s.mux.Lock()
	defer s.mux.Unlock()
	log.SpanLog(ctx, log.DebugLevelMetrics, "track k8s AppInst", "key", appInst.Key, "labelKey", labelKey, "labelKeyOld", labelKeyOld, "track", track)
	if s.labels == nil {
		s.labels = make(map[cloudcommon.AppInstLabels]AppInstLabelInfo)
		s.labelsOld = make(map[cloudcommon.AppInstLabelsOld]AppInstLabelInfo)
	}
	if track {
		info := AppInstLabelInfo{
			AppInstKey: appInst.Key,
			AppKey:     appInst.AppKey,
		}
		s.labels[labelKey] = info
		s.labelsOld[labelKeyOld] = info
	} else {
		delete(s.labels, labelKey)
		delete(s.labelsOld, labelKeyOld)
	}
}

func (s *AppInstLabels) getAppInstInfoFromLabels(labels map[string]string) (AppInstLabelInfo, bool) {
	return s.getAppInstInfo(getAppInstLabelKeys(labels))
}

func (s *AppInstLabels) getAppInstInfo(labelKey cloudcommon.AppInstLabels, labelKeyOld cloudcommon.AppInstLabelsOld) (AppInstLabelInfo, bool) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if labelKey.AppInstNameLabel != "" {
		if info, found := s.labels[labelKey]; found {
			return info, found
		}
	}
	if labelKeyOld.AppNameLabel != "" {
		if info, found := s.labelsOld[labelKeyOld]; found {
			return info, found
		}
	}
	return AppInstLabelInfo{}, false
}

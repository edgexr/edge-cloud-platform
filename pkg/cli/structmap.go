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

package cli

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

// GetStructMap converts the object to a StructMap.
func GetStructMap(obj interface{}, ops ...GetStructMapOp) (*MapData, error) {
	opts := &GetStructMapOptions{}
	for _, op := range ops {
		op(opts)
	}

	// convert fields to map for easy lookup
	var fmap *edgeproto.FieldMap
	if opts.fieldFlags != nil && len(opts.fieldFlags) > 0 {
		fmap = edgeproto.MakeFieldMap(opts.fieldFlags)
	}

	data := getStructMap(fmap, []string{}, reflect.ValueOf(obj), opts)
	if data == nil {
		// no data generated
		data = make(map[string]interface{})
	}
	if dmap, ok := data.(map[string]interface{}); ok {
		return &MapData{
			Namespace: StructNamespace,
			Data:      dmap,
		}, nil
	}
	return nil, fmt.Errorf("GetStructMap object is not a struct")
}

func getStructMap(fmap *edgeproto.FieldMap, parentFields []string, v reflect.Value, opts *GetStructMapOptions) interface{} {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		return getStructMap(fmap, parentFields, v.Elem(), opts)
	} else if v.Kind() == reflect.Struct {
		if _, ok := v.Interface().(json.Marshaler); ok {
			// The struct has MarshalJSON function defined, so
			// treat it like a basic type and do not recurse.
			// In particular, time.Time implements
			// json.Marshaler, and has no exported fields,
			// so requires the marshaler to output any data
			// during marshaling.
			if v.IsZero() {
				return nil
			}
			return v.Interface()
		}
		data := make(map[string]interface{})
		for ii := 0; ii < v.NumField(); ii++ {
			sf := v.Type().Field(ii)
			// skip unexported fields
			if sf.PkgPath != "" {
				continue
			}

			subFields := []string{}
			if fmap != nil {
				// protobuf field tag is needed
				ptag, ok := getProtoTag(sf)
				if !ok {
					continue
				}
				ftag := strings.Join(append(parentFields, ptag), ".")
				if !fmap.HasOrHasChild(ftag) {
					continue
				}
				subFields = append(parentFields, ptag)
			}
			// get name we should use as key based on namespace
			name := GetFieldTaggedName(sf, StructNamespace)
			subv := v.Field(ii)
			subdata := getStructMap(fmap, subFields, subv, opts)
			if opts.omitEmpty && subdata == nil {
				continue
			}
			data[name] = subdata
		}
		if opts.omitEmpty && len(data) == 0 {
			return nil
		}
		return data
	} else if v.Kind() == reflect.Map {
		if v.Type().Key().Kind() != reflect.String {
			// only maps with strings keys are allowed
			return nil
		}
		data := make(map[string]interface{})
		iter := v.MapRange()
		for iter.Next() {
			key := iter.Key().String()
			subv := iter.Value()
			subdata := getStructMap(fmap, parentFields, subv, opts)
			if opts.omitEmpty && subdata == nil {
				continue
			}
			data[key] = subdata
		}
		if opts.omitEmpty && len(data) == 0 {
			return nil
		}
		return data
	} else if v.Kind() == reflect.Slice {
		data := make([]interface{}, 0)

		for ii := 0; ii < v.Len(); ii++ {
			subv := v.Index(ii)
			subdata := getStructMap(fmap, parentFields, subv, opts)
			if opts.omitEmpty && subdata == nil {
				continue
			}
			data = append(data, subdata)
		}
		if opts.omitEmpty && len(data) == 0 {
			return nil
		}
		return data
	}
	if opts.omitEmpty && v.IsZero() {
		return nil
	}
	return v.Interface()
}

func getProtoTag(sf reflect.StructField) (string, bool) {
	tag := sf.Tag.Get("protobuf")
	tagvals := strings.Split(tag, ",")
	if len(tagvals) < 2 {
		return "", false
	}
	return tagvals[1], true
}

type GetStructMapOptions struct {
	fieldFlags []string
	omitEmpty  bool
}

type GetStructMapOp func(opts *GetStructMapOptions)

// Only include fields specified by the field flags, which
// are based on the protobuf id tag.
func WithStructMapFieldFlags(fieldFlags []string) GetStructMapOp {
	return func(opts *GetStructMapOptions) { opts.fieldFlags = fieldFlags }
}

// Omit empty fields.
func WithStructMapOmitEmpty() GetStructMapOp {
	return func(opts *GetStructMapOptions) { opts.omitEmpty = true }
}

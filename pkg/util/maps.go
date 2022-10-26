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

package util

// Make a copy of a string map
// if the source map is nil, the result is an empty map
func CopyStringMap(srcM map[string]string) map[string]string {
	mapCopy := map[string]string{}
	if srcM == nil {
		return mapCopy
	}
	for k, v := range srcM {
		mapCopy[k] = v
	}
	return mapCopy
}

func AddMaps(maps ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}

func AddStringSliceUniques(ss []string, add []string) []string {
	m1 := map[string]struct{}{}
	for _, val := range ss {
		m1[val] = struct{}{}
	}
	for _, val := range add {
		if _, found := m1[val]; !found {
			ss = append(ss, val)
		}
	}
	return ss
}

func RemoveStringSliceUniques(ss []string, rm []string) []string {
	rmMap := map[string]struct{}{}
	for _, val := range rm {
		rmMap[val] = struct{}{}
	}
	news := []string{}
	for _, val := range ss {
		if _, found := rmMap[val]; found {
			continue
		}
		news = append(news, val)
	}
	return news
}

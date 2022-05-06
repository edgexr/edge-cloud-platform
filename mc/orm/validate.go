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

package orm

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/edgexr/edge-cloud/util"
)

func ValidName(name string) error {
	err := util.ValidObjName(name)

	// Gorm DB create works only for name <= 90
	// Also, JFrog Artifactory repo name is created from OrgName and it must be <= 64
	// In future, if we move away from artifactory, this limitation needs to be revisited.
	const (
		orgNameMax = 64
	)

	if err != nil {
		return err
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("Name cannot start with '.'")
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("Name cannot start with '-'")
	}
	if strings.HasSuffix(name, ".") {
		return fmt.Errorf("Name cannot end with '.'")
	}
	if strings.Contains(name, "::") {
		return fmt.Errorf("Name cannot contain ::")
	}
	if strings.Contains(name, "&") {
		return fmt.Errorf("Name cannot contain &")
	}
	if strings.HasSuffix(name, ".git") {
		return fmt.Errorf("Name cannot end with '.git'")
	}
	if strings.HasSuffix(name, ".atom") {
		return fmt.Errorf("Name cannot end with '.atom'")
	}
	if strings.HasSuffix(name, "-cache") {
		return fmt.Errorf("Name cannot end with '-cache'")
	}
	if len(getArtifactoryRepoName(name)) > orgNameMax {
		return fmt.Errorf("Name too long")
	}
	return nil
}

func ValidNameNoUnderscore(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if strings.Contains(name, "_") {
		return fmt.Errorf("Name cannot contain _")
	}
	return nil
}

// Gitlab groups can only contain letters, digits, _ . -
// cannot start with '-' or end in '.', '.git' or '.atom'
// This combines the rules for both name and path.
func GitlabGroupSanitize(name string) string {
	name = strings.TrimPrefix(name, "-")
	name = strings.TrimSuffix(name, ".")
	if strings.HasSuffix(name, ".git") {
		name = name[:len(name)-4] + "-git"
	}
	if strings.HasSuffix(name, ".atom") {
		name = name[:len(name)-5] + "-atom"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsNumber(r) ||
			r == '_' || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, name)
}

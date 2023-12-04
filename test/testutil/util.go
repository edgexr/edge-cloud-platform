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

package testutil

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
)

//based on the api some errors will be converted to no error
func ignoreExpectedErrors(api string, key objstore.ObjKey, err error) error {
	if err == nil {
		return err
	}
	if api == "delete" {
		if strings.Contains(err.Error(), key.NotFoundError().Error()) {
			log.Printf("ignoring error on delete : %v\n", err)
			return nil
		}
	} else if api == "create" {
		if strings.Contains(err.Error(), key.ExistsError().Error()) {
			log.Printf("ignoring error on create : %v\n", err)
			return nil
		}
	}
	return err
}

func unwrapGrpcError(err error) error {
	if err == nil {
		return nil
	}
	// This allows require.Nil(t, err) to actually print
	// the contents of the error, instead of just the Status type.
	if st, ok := status.FromError(err); ok {
		return errors.New(st.String())
	}
	return err
}

func (s *DebugDataOut) Sort() {
	for ii := 0; ii < len(s.Requests); ii++ {
		sort.Slice(s.Requests[ii], func(i, j int) bool {
			// ignore name for sorting
			ikey := s.Requests[ii][i].Node
			ikey.Name = ""
			jkey := s.Requests[ii][j].Node
			jkey.Name = ""
			return ikey.GetKeyString() < jkey.GetKeyString()
		})
	}
}

// CompareExpectedData is used for tests that generate data and want to
// compare it to expected data in a file. Typically this for testing
// configuration file generation.
// GeneratedData should be blank if the generated data is already in the
// generated file named "fileNameRoot.fileType".
func CompareExpectedFileData(t *testing.T, fileNameRoot, fileType, generatedData string) {
	genFile := fileNameRoot + "." + fileType
	expFile := fileNameRoot + "-expected." + fileType

	if generatedData != "" {
		// write to generated file
		os.WriteFile(genFile, []byte(generatedData), 0644)
	}
	diffArgs := []string{"-au", "-I", "# .*", expFile, genFile}
	cmd := exec.Command("diff", diffArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(string(out))
		require.True(t, false, "compare failed for "+fileNameRoot)
	}
}

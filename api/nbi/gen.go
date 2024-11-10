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

// git clone https://github.com/edgexr/oapi-codegen
// (cd oapi-codegen/cmd/oapi-codegen && go install .)

//go:generate oapi-codegen --config=config.yaml openapi/Edge-Application-Management.yaml

// For reference, if using official oapi-codegen:
//**go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=config.yaml openapi/Edge-Application-Management.yaml

package nbi

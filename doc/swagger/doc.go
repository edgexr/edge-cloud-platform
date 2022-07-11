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

// Master Controller (MC) API Documentation
//
// # Introduction
// The Master Controller (MC) serves as the central gateway for orchestrating edge applications and provides several services to both application developers and operators. For application developers, these APIs allow the management and monitoring of deployments for edge applications. For infrastructure operators, these APIs provide ways to manage and monitor the usage of cloudlet infrastructures. Both developers and operators can take advantage of these APIS to manage users within the Organization.
//
// You can leverage these functionalities and services on our easy-to-use MobiledgeX Console. If you prefer to manage these services programmatically, the available APIs and their resources are accessible from the left navigational menu.
//
//     Schemes: https
//     BasePath: /api/v1
//     Version: 2.0
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     SecurityDefinitions:
//     Bearer:
//          type: apiKey
//          name: Authorization
//          in: header
//          description: Use [login API](#operation/Login) to generate bearer token (JWT) for authorization. Usage format - `Bearer <JWT>`
//
// swagger:meta
package doc

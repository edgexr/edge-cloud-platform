// Master Controller (MC) API Documentation
//
// # Introduction
// The Master Controller (MC) serves as the central gateway for orchestrating edge applications and provides several services to both application developers and operators. For application developers, these APIs allow the management and monitoring of deployments for edge applications. For infrastructure operators, these APIs provide ways to manage and monitor the usage of cloudlet infrastructures. Both developers and operators can take advantage of these APIS to manage users within the Organization.
//
// You can leverage these functionalities and services on our easy-to-use MobiledgeX Console. If you prefer to manage these services programmatically, the available APIs and their resources are accessible from the left navigational menu.
//
//     Schemes: https
//     BasePath: /api/v1
//     Version: 1.0.0
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

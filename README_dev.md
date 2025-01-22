# Development

We welcome all kinds of contributions to help improve the code.
This doc covers some of the basics to get you started.

## Technologies

The edge cloud platform leans heavily on the following open source
technologies:

- [Protocol Buffers](https://protobuf.dev/), used to define all of
our APIs and data models. We also have custom generators under [tools](./tools/) for generating test code, notify framework code, API related code, etc. from the protobuf definitions. This helps us reduce the amount of boiler-plate code we'd otherwise need to write
by hand.
- [GRPC](https://grpc.io/): all of our internal service-to-service
communication is done via GRPC, using the protobuf definitions.
- [Jaeger](https://www.jaegertracing.io/): used to implement
Opentracing, all of our [logging](./pkg/log/spanlog.go) writes to
both stdout and Jaeger.
- [Etcd](https://etcd.io/): Etcd is used for storing persistent
data.
- [Echo](https://echo.labstack.com/) is used as our REST API
framework in cases where we are not using GRPC.

## APIs

Apis are defined under the api directory. There are three main sets
of API definitions:

- [edgeproto](./api/edgeproto/): contains Protobuffer definitions
all of our Northbound interface APIs for managing applications,
clusters, edge-sites (cloudlets), application instances, policies,
etc. These define both the data models and the primarily CRUD-style
APIs.
- [distributed_match_engine](./api/distributed_match_engine/):
contains generated files from [edge-proto](https://github.com/edgexr/edge-proto)
that define the UNI discovery APIs for clients and devices to
discover the "best" application instance to connect to.
- [nbi](./api/nbi): contains go code generated from the
[CAMARA NBI API](https://github.com/camaraproject/EdgeCloud/blob/main/code/API_definitions/Edge-Application-Management.yaml)
OpenAPI spec, for which we keep a potentially modified
[copy](./api/nbi/openapi). CAMARA NBI APIs calls get converted
to our internal data structures and API calls.

## Services and Code

All services are defined under [cmd](./cmd), but are typically
just calls to package code. The primary services to explore are:

- [Controller](./pkg/controller/controller.go): handles all incoming
API calls to CRUD objects, validates, resolves dependencies,
checks resource availability and user requirements, decides
where instances will be deployed, and then commits changes to an
Etcd database. It then forwards changes to the CCRM/CRM to actually
implement changes on the infrastructure.
- [CCRM](./pkg/ccrm/ccrm.go): handles API calls from the Controller
to create infrastructure specific objects, such as clusters and
application instances, by converting our internal protobuf-based
data models to infrastructure-specific API calls. This service
also interacts with Etcd, but in a read-only mode. All of the
platform-specific code is under [pkg/platform](./pkg/platform).
Adding new platforms is as simple as implementing the
[Platform interface](./pkg/platform/platform.go) and adding it to
the list of [all platforms](./pkg/platform/platforms/platforms.go).
CCRM shares code with [CRM](./pkg/crm/crm.go), which is the
on-edge-site CRM service. The shared code is the [CRMHandler](./pkg/crmutil/controller-data.go). We are moving away from the
on-edge-site CRM service, but some platforms (Openstack/VCD)
have not been fully converted to allow them to run under the CCRM
yet.

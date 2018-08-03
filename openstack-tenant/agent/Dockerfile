FROM mobiledgex/build AS build

WORKDIR /go/src/github.com/mobiledgex/edge-cloud-infra/
COPY . .
ENV CGO_ENABLED=0
ENV GOPATH=/go
ENV PATH="/go/bin:${PATH}"
WORKDIR /go/src/github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent
RUN go get -d -v ./...
RUN go install -v ./...
RUN ls -l /go/bin
FROM alpine:latest

COPY --from=build /go/bin/agent /usr/local/bin/mexosagent

ENTRYPOINT [ "mexosagent" ]
CMD []

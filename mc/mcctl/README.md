# Master Controller CLI - Developer README

The master controller CLI (mcctl) implements a command line interface to the master controller. It is intended as a developer-facing secondary tool, where the primary user interface is the web UI. Usage of the mcctl itself should be self-documenting, so usage is not covered here. Instead, this readme focuses on where code lives and what it does.

For MC API development, consider the following directories in the edge-cloud-infra repo:

```
mc/orm                MC code (echo framework)
mc/ormapi             MC api struct definitions (no functions)
mc/ormclient          client api definitions and code for connecting to MC
mc/mcctl/cli          cli library for parsing input args to objs/json
mc/mcctl/ormctl       cobra command for mcctl
mc/mcctl/cliwrapper   client library wrapped around mcctl for testing
```

For testing, e2e tests uses the client interface defined in ```mc/ormclient/clientapi.go```. This allows it to switch between direct REST API calls from ```mc/ormclient``` and wrapped API calls that actually use mcctl from ```mc/mcctl/cliwrapper```.

When adding a new API, the back-end handling code will likely be in ```mc/orm```, with any structs using for transport defined in ```mc/ormapi```. If a cli is desired, it should be defined in ```mc/mcctl/ormctl```, with a client api implemented in ```mc/ormclient``` and a client api wrapper in ```mc/mcctl/cliwrapper```.

Functionality is really limited to a few files, while the rest just define functions/APIs based on those building block code. Those files are:

```
mc/ormclient/rest_client.go      POST JSON http functions
mc/mcctl/ormctl/cmd.go           generate cobra commands for mcctl
mc/mcctl/cliwrapper/wrapcli.go   convert objs to/from exec'ing mcctl cli
```

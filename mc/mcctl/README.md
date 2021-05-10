# Master Controller CLI - Developer README

The master controller CLI (mcctl) implements a command line interface to the master controller. It is intended as a developer-facing secondary tool, where the primary user interface is the web UI. Usage of the mcctl itself should be self-documenting, so usage is not covered here. Instead, this readme focuses on where code lives and what it does.

For MC API development, consider the following directories in the edge-cloud-infra repo:

```
mc/orm                   MC code (echo framework)
mc/ormapi                MC api struct definitions (no functions)
mc/ormclient             Rest client code for connecting to MC
mc/mcctl/ormctl          MC client API definitions (no functions)
mc/mcctl/cli             Cli library for parsing input args to objs/json
mc/mcctl/mccli           Mcctl library to build cobra.Command hierarchy for mcctl
mc/mcctl/cliwrapper      Client library wrapped around mcctl for testing
mc/mcctl/genmctestclient Generator for object-specific client funcs
mc/mcctl/mctestclient    Object-specific client funcs to call into Rest/Cliwrapper clients
```

For testing, e2e tests uses the client functions defined in ```mc/mcctl/mctestclient```. These are object-specific functions to make test code easy to write. The mctestclient uses a ClientRun object, which is either from the Rest client code ```mc/ormclient``` or the cliwrapper ```mc/mcctl/cliwrapper```. This allows it to switch between direct REST API calls from ```mc/ormclient``` and wrapped API calls that actually use mcctl from ```mc/mcctl/cliwrapper```.

When adding a new API, the back-end handling code will likely be in ```mc/orm```, with any structs using for transport defined in ```mc/ormapi```. On the client side, the API should also be defined in the ```mc/mcctl/ormctl``` library. This will generate a client function in the mctestclient. You may also need to edit ```mc/mcctl/mccli/rootcmd.go``` to add it to mcctl if it not already part of an existing group. No other changes should be needed unless you need custom functionality.

Functionality is really limited to a few files, while the rest just define functions/APIs based on those building block code. Those files are:

```
mc/ormclient/rest_client.go      POST JSON http functions
mc/mcctl/ormctl/cmd.go           generate cobra commands for mcctl
mc/mcctl/cliwrapper/wrapcli.go   convert objs to/from exec'ing mcctl cli
```

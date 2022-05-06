# Master Controller CLI - Developer README

The master controller CLI (mcctl) implements a command line interface to the master controller (MC). It is intended as a developer-facing secondary tool, where the primary user interface is the web UI. Usage of the mcctl itself should be self-documenting, so usage is not covered here. Instead, this readme focuses on where code lives and what it does.

For MC API development, consider the following directories in the edge-cloud-infra repo:

```
mc/orm                   MC server code (echo framework)
mc/ormapi                MC api struct definitions (no functions)
mc/ormutil               Common utility functions shared between client and server
mc/ormclient             Rest client code for connecting to MC
mc/mcctl/ormctl          MC client API definitions (no functions)
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

## Test Clients

As noted earlier, the mctestclient is the abstract interface for testing, which accepts a common set of functions and either uses the rest client or the cliwrapper underneath. For Creates and Deletes, the mctestclient functions take as input Structs. For Updates, the mctestclient functions take input as MapData, which is map[string]interface{} data with an associated Namespace. The MapData implicitly defines which fields to update and which to ignore, regardless of whether values are empty (0, nil, "", etc) or not.

The mctestclient is used directly in unit-test code. However, layered on top of the mctestclient is the e2e-test code, which reads in YAML files and then calls the mctestclient APIs to send the data to MC under test.

It is worth noting the various ways data is transformed in these scenarios. The goal is to allow the same input data to be used to test either the rest client or the mcctl client in both unit and e2e tests. Scenarios are noted below, with functions in parentheses. The final JSON is sent to the MC.

Production:
1. mcctl: args (ParseArgs) -> MapData (cli.JsonMap) -> JSON-MapData (json.Marshal) -> JSON

Unit-Test scenarios:
1. same as (1) above
2. rest-client create/delete: Struct (json.Marshal) -> JSON
3. rest-client update: MapData (rest_client.Run) -> JSON-MapData (json.Marshal) -> JSON
4. cliwrapper create/delete: Struct (GetStructMap) -> MapData (cli.MarshalArgs) -> args -> (1)
5. cliwrapper update: MapData (MarshalArgs) -> args -> (1)

E2E-Test scenarios (mcapi.go)
5. create/delete: YamlFile (yaml.Unmarshal) -> Struct -> (2) or (4) above
6. update: YamlFile (yaml.Unmarshal) -> MapData -> (3) or (5) above

## Federation EWBI Openapi Spec

Here contains the official Federation EWBI (East-West Bound Interface)
API spec as `FederationApi_v1.3.0-official.yaml` ([source](https://www.gsma.com/futurenetworks/resources/platform-group-4-0-federation-api-1-0-0-yaml/), [download](https://www.gsma.com/futurenetworks/wp-content/uploads/2022/10/OPG.04-v1.0-1.zip), a modified version as `FederationApi_v1.3.0.yaml`, and a Makefile to generate both API struct models and golang Echo server stubs.

### Generators

We use two generators as part of the doc/fedapi files:

- [oapi-codegen](https://github.com/deepmap/oapi-codegen) to generate Echo server stubs. Unfortunately this generator does not generate structs for callback objects, so is not used for generating struct objects. This generates a single file, `pkg/mc/federation/ewbi-server.gen.go`.

- [openapi-generator](https://github.com/OpenAPITools/openapi-generator) for generating API structs. This tool seems to be better supported and more fully featured, but it's targeted towards client generator, and thus has no server-side stubs generator. This generates all the files in `pkg/fedewapi`.

To generate, just run
```bash
make
```

### Changes

We have several modifications to the official yaml which are documented as patches in the `patches` directory. To add a new change:

- First make a copy of the current yaml
  ```bash
  cp FederationApi_v1.3.0.yaml FederationApi_v1.3.0.yaml.last
  ```
- Make your changes to FederationApi_v1.3.0.yaml
- Generate a diff of your changes (number is important to apply patches in order)
  ```bash
  diff -au FederationApi_v1.3.0.yaml.last FederationApi_v1.3.0.yaml > patches/##-my-change-desc.patch
  ```

### Updating Official Spec

If updating the official spec:

- Copy new spec to `FederationApi_v1.3.0-official.yaml`
- Make sure to convert above file from DOS format to Unix line endings
- Copy official to local:
  ```bash
  cp FederationApi_v1.3.0-official.yaml FederationApi_v1.3.0.yaml
  ```
- Reapply our patches
  ```bash
  patch < patches/*
  ```

If some our changes are upstreamed, the patch file for that change
can be removed.

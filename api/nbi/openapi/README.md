## Federation EWBI Openapi Spec

Here contains:

- The official CAMARA NBI (North Bound Interface) API spec as `Edge-Application-Management-official.yaml` ([source](https://github.com/camaraproject/EdgeCloud/tree/main/code/API_definitions)
- A potentially modified version as `Edge-Application-Management.yaml`

## Generators

We use [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen) to generate Echo server stubs and model structs. To generate the data, in `api/nbi`, run `go generate`.

## Changes

We may have several modifications to the official yaml which are documented as patches in the `patches` directory. To add a new change:

- First make a copy of the current yaml
  ```bash
  cp Edge-Application-Management.yaml Edge-Application-Management.yaml.last
  ```
- Make your changes to Edge-Application-Management.yaml
- Generate a diff of your changes (number is important to apply patches in order)
  ```bash
  diff -au Edge-Application-Management.yaml.last Edge-Application-Management.yaml > patches/##-my-change-desc.patch
  ```

## Updating Official Spec

If updating the official spec:

- Copy new spec to `Edge-Application-Management-official.yaml`
- Make sure to convert above file from DOS format to Unix line endings
- Copy official to local:
  ```bash
  cp Edge-Application-Management-official.yaml Edge-Application-Management.yaml
  ```
- Reapply our patches
  ```bash
  patch < patches/*
  ```

If some our changes are upstreamed, the patch file for that change
can be removed.

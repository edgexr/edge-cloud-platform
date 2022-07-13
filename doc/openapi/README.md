Openapi 3.0 documentation for user facing (Master Controller) APIs.

_mc-openapi.yaml_: Full API spec. Use for tooling as it is too big for human readability.
_groups/*.yaml_: APIs broken into groups for human readability. Each yaml file is a separate openapi doc and stands on its own, and thus may have redundant information with the other files.

All documentation is auto-generated based on the code. To regenerate the files, run

```
make doc
```

To browse the documentation in a web browser, run

```
make local-server
```

and point your web browser to `http://localhost:1081`


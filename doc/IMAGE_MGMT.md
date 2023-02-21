# Image and Application Management

Images are either docker containers, VM images, or Helm charts.
Applications are developer defined objects created on our platform
that specify how images are deployed on edge infrastructure and are
connected to the outside world.

In this document we use {DOMAIN} or $DOMAIN to refer to the specific platform domain,
for example "main.edgexr.org".

On the command line for bash, DOMAIN can be set via:
```bash
export DOMAIN=main.edgexr.org
```

## Container Management

Containers are managed in Harbor. Credentials for Harbor are your platform user credentials.
Container images can be managed via UI by pointing your web browser to `https://docker.{DOMAIN}`,
or by docker command line or any other tools that adhere to the docker registry API specification.
This document assumes you are familiar with managing images via docker cli.

The UI is useful for browsing images, but pushing and pulling images is done via the docker cli.

### Docker login

Use your platform user credentials to log in.
```bash
docker login https://docker.$DOMAIN
```

### Image Names

Images should be tagged with the developer organization as the start of the image path.
You will only be able to access images in developers orgs that you have access to.

```bash
docker tag <local-image> https://docker.$DOMAIN/<developer-org>/<myimage>:<tag>
```

### Push image to the platform

```bash
docker push https://docker.$DOMAIN/<developer-org>/<myimage>:<tag>
```

### List images

Docker cli doesn't provide a good way to list remote images, instead use the UI.

### Updating images

Containers are updated by rebuilding the container, and running docker push.
It is recommended that new tags are used for every new version of a container
to be able to track different versions, but it is not required.

### Direct API access

Harbor adheres to the [docker registry API V2](https://docs.docker.com/registry/spec/api/),
but it is not recommended to use direct API access. Instead, use docker,
[scopeo](https://github.com/containers/skopeo), or other tools that implement the
docker registry API spec.

## VM Image Management

VM images are stored in our VM registry. Currently we use mcctl to manage the images.
Images are stored by developer organization. You will only be able to manage images
for developer organizations that your have permissions for.

### Login via mcctl

```bash
mcctl --addr https://console.$DOMAIN login username=<username>
```

For direct REST access, your $TOKEN is in `~/.mctoken.yml` after logging in via mcctl.
Note that tokens expire after 24 hours.

### List Images

```bash
mcctl --addr https://console.$DOMAIN artifact show org=<developer-org>
```

### Upload local image

```bash
mcctl --addr https://console.$DOMAIN artifact upload org=<developer-org> path=<remote-image-name> localfile=<path-to-local-image>
```

### Show info for remote image

```bash
mcctl --addr https://console.$DOMAIN artifact info org=<developer-org> path=<remote-image-name>
```

### Download an image

```bash
mcctl --addr https://console.$DOMAIN artifact download org=<developer-org> path=<remote-image-name> localfile=<destination-path>
```

### Delete remote image

```bash
mcctl --addr https://console.$DOMAIN artifact delete org=<developer-org> path=<remote-image-name>
```

### Updating images

New versions of images can be updated by deleting the existing image and uploading a new one.
Images have md5sums to be able to distinguish between different images of the same name.
For major changes, we recommend using different names for the images instead of relying on the image hash.

### Direct API access

Direct API access is via REST. Use mcctl with `--debug` to print out example curl commands.

## Application Version Management

Applications are stored in our platform database, and are updated either via the UI
at `https://console.$DOMAIN`, via the mcctl command line utility, or directly via REST APIs.

This document only describes version management of Applications.

### Application Versions

The Application Version is immutable, and is meant to be like a container image tag,
that is used to identify the specific configuration of the Application.

### Application Update

Applications can be updated via the update GUI menu command, or the mcctl/REST app
update APIs commands/APIs. Some fields are not updatable, and some fields are not
updatable if instances have already been deployed.

On the UI, from the App page, click on the "Actions -> Update" menu for
the specific App.

For mcctl, use
```bash
mcctl --addr https://console.$DOMAIN app update
```

### Application Revision after Update

When an App definition is updated, existing deployed instances of the application are
not updated. This is to allow the developer to control when and which instances are
updated.

When the definition is updated, a Revision field on the App is automatically updated.
App Instances also have a Revision field, that specify the revision of the App when
it was deployed. This allows the developer to see which deployed instances now differ
from the App definition.

### Application Instance Upgrade

The Upgrade command for App Instances allows the instance to be redeployed from the
current App revision. On the GUI, this option only appears if the App revision and
App Instance revision are different. Depending on the deployment type and deployment
parameters, upgrading may cause a service outage for the App Instance. For example,
upgrading a single docker instance will cause an outage, but upgrading a kubernetes
deployment will use a rolling upgrade to avoid an outage.

On the UI, from the App Instances page, click on the "Actions -> Upgrade" menu for
the specific App Instance.

For mcctl, use
```bash
mcctl --addr https://console.$DOMAIN appinst refresh
```

### Direct API access

Direct API access is via REST. Use mcctl with `--debug` to print out example curl commands.
